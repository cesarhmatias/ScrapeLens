# Test-only switches in the App

Environment variables and command-line actions that only the test suites use. They
live behind the Cargo feature `test-hooks`, which is **off** in release builds. A release
build reads none of them and accepts no command-line test action.

Build a test binary with `cargo build --features test-hooks` (or run the tests with
`cargo test --features test-hooks`).

| Name | Where | Decision |
|---|---|---|
| `SCRAPELENS_TEST_MODE` | App: list log, command-line actions, proxy loopback | Gated (`test-hooks`) |
| `SCRAPELENS_CAPTURE_HEADLESS` | App: capture options | Gated (`test-hooks`); release is headed |
| `SCRAPELENS_CAPTURE_IGNORE_CERT` | App: capture options | Gated (`test-hooks`); release keeps certificate checks on |
| `SCRAPELENS_CAPTURE_NETWORK` | App: `NetworkMode::from_env` | Gated in the App (`test-hooks`); release uses the open network. The capture crate still defines the parser; its own gate is pending in `capture/` |
| `SCRAPELENS_TEST_PROXY_BYPASS_LOOPBACK` | App: proxy loopback bypass | Gated (`test-hooks`) |
| `SCRAPELENS_CAPTURE_URL` | App: suggested start URL | Gated (`test-hooks`) |
| `SCRAPELENS_CDP_TRANSPORT` | capture crate (`transport.rs`) | Pending: the capture crate reads it in release. Decision: gate it in `capture/` with the same feature |
| `SCRAPELENS_TEST_PROXY_CA` | capture crate (`relay.rs`) | Pending: read in release. Decision: gate it in `capture/` |
| `SCRAPELENS_RELAY_PEER_PROBE` | capture crate (`relay.rs`, test helper) | Pending: read in release. Decision: gate it in `capture/` |
| `SCRAPELENS_PROXY_URL` | MCP (`mcp/src/live.rs`) | Kept: a product option (`proxy: "env"`), documented in the README |

Command-line test actions (`--import-har`, `--import-netlog`, `--open-capture`) are in
`src/cli_test.rs`, compiled only with `test-hooks`.

Harnesses that depend on these switches must build with `--features test-hooks`:
`src-tauri/linux/build.sh` (the Xvfb smoke) and the proxy acceptance scripts under
`experiments/proxy/`.

## Check on a release binary

`strings target/release/scrapelens` (`cargo build --release`, no features) finds none of
the App's test variables or command-line flags (`SCRAPELENS_CAPTURE_IGNORE_CERT`,
`SCRAPELENS_CAPTURE_HEADLESS`, `SCRAPELENS_TEST_MODE`,
`SCRAPELENS_TEST_PROXY_BYPASS_LOOPBACK`, `SCRAPELENS_CAPTURE_URL`,
`SCRAPELENS_CAPTURE_NETWORK`, `SCRAPELENS_RELAY_PEER_PROBE`, `--import-har`,
`--open-capture`). Still present, from the capture crate, until its own gate lands:
`SCRAPELENS_CDP_TRANSPORT` and `SCRAPELENS_TEST_PROXY_CA`.
