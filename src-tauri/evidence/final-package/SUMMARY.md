# Final package

Source: `main` at `2504153` (`docs: Keychain prompt and how to remove the security tool's
access (T06, T10)`), which includes T09. The build started at 11:59:41 and the executable was
written at 12:01:57 on 2026-11-07. The commits made during the build only change documentation.

Build: `./app/node_modules/.bin/tauri build --bundles app`, from the root. Signing: the local
self-signed identity `ScrapeLens Local Signing`, with no Developer ID and no notarization (the
log records "skipping app notarization").

| Item | Value |
|---|---|
| Executable | `target/release/bundle/macos/ScrapeLens.app/Contents/MacOS/scrapelens` |
| SHA-256 | `ec53aef44d7dc5cf9ba1621f8e9d7a6ebdbbab4370756c7d5555136f31cd016d` |
| Executable size | 26 096 512 bytes |
| `.app` size | 26 224 KiB |
| `codesign --verify --deep --strict` | valid on disk; satisfies its Designated Requirement |
| Designated requirement | `identifier "app.scrapelens.desktop" and certificate root = H"d0a53befa59a447043abc9e58a3381addbbf1751"` |
| Architecture | arm64 |
| Test strings in the binary | none of the test variables listed in PACKAGING.md |
| `remote-allow-origins` in the binary | 0 occurrences |

Core tests before the build: `cargo test -p scrapelens-core`, exit 0. Only the core suite ran
for this package.

Launch without focus: `open -g` on the bundle. The process stayed alive and the "ScrapeLens"
window (1440×920) appeared in the window list. `screencapture -l` came out blank, with a dark
background, in both attempts (about 8 s and 18 s). The rendered window was not verified. A
screenshot with content needs the app in front; the leader waived it for this package. The test
process was stopped.
