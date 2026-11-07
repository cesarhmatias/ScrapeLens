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
| `SCRAPELENS_CAPTURE_NETWORK` | App: `NetworkMode::from_env` | Gated (`test-hooks`, App and capture crate); release uses the open network |
| `SCRAPELENS_TEST_PROXY_BYPASS_LOOPBACK` | App: proxy loopback bypass | Gated (`test-hooks`) |
| `SCRAPELENS_CAPTURE_URL` | App: suggested start URL | Gated (`test-hooks`) |
| `SCRAPELENS_CDP_TRANSPORT` | capture crate (`transport.rs`) | Gated (`test-hooks`) in `capture/`, chained from the App's feature |
| `SCRAPELENS_TEST_PROXY_CA` | capture crate (`relay.rs`) | Gated (`test-hooks`) in `capture/`, chained from the App's feature |
| `SCRAPELENS_RELAY_PEER_PROBE` | capture crate (`relay.rs`, test helper) | Not in the App binary in either build (test helper in the capture crate) |
| `SCRAPELENS_PROXY_URL` | MCP (`mcp/src/live.rs`) | Kept: a product option (`proxy: "env"`), documented in the README |

Command-line test actions (`--import-har`, `--import-netlog`, `--open-capture`) are in
`src/cli_test.rs`, compiled only with `test-hooks`.

Harnesses that depend on these switches must build with `--features test-hooks`:
`src-tauri/linux/build.sh` (the Xvfb smoke) and the proxy acceptance scripts under
`experiments/proxy/`.

## Check on a release binary

`strings target/release/scrapelens` (from the root; `cargo build --release -p scrapelens`, no features) finds none of
the App's test variables or command-line flags (`SCRAPELENS_CAPTURE_IGNORE_CERT`,
`SCRAPELENS_CAPTURE_HEADLESS`, `SCRAPELENS_TEST_MODE`,
`SCRAPELENS_TEST_PROXY_BYPASS_LOOPBACK`, `SCRAPELENS_CAPTURE_URL`,
`SCRAPELENS_CAPTURE_NETWORK`, `SCRAPELENS_RELAY_PEER_PROBE`, `--import-har`,
`--open-capture`).

Result on 2026-11-06 (`cargo build --release`, no features; SHA-256 of the binary
`9d06303111976b218da48e912177c952a2e169cae759c5de679e1cb7a8871462`): none of the nine
variables above is in the binary. Positive control, same tree with `--features test-hooks`:
`SCRAPELENS_TEST_PROXY_CA`, `SCRAPELENS_CDP_TRANSPORT`, `SCRAPELENS_CAPTURE_NETWORK`,
`SCRAPELENS_CAPTURE_IGNORE_CERT`, `SCRAPELENS_TEST_PROXY_BYPASS_LOOPBACK`,
`SCRAPELENS_CAPTURE_URL` and `SCRAPELENS_CAPTURE_HEADLESS` are present, so the search works.
`SCRAPELENS_RELAY_PEER_PROBE` is absent in both builds.
