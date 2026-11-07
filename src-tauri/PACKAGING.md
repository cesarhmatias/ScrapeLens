# Packaging

How the ScrapeLens packages are built, what each one contains and where the official builds run.
Earlier release measurements and bundle hashes are in [PACKAGING-HISTORY.md](PACKAGING-HISTORY.md).

## Official builds

The official builds run in GitHub Actions. The workflows do not publish anything: the release
workflow opens a draft release, which a maintainer reviews and publishes.

- [`.github/workflows/pr-ci.yml`](../.github/workflows/pr-ci.yml): `cargo test`, clippy and the App's
  `npm test` on Linux and macOS, for every pull request.
- [`.github/workflows/release.yml`](../.github/workflows/release.yml): on a `v*.*.*` tag, builds the
  Linux packages (x86_64 and arm64) and the macOS arm64 app, writes SHA-256 sums, creates build
  provenance attestations and opens a draft release.

Neither workflow has run on GitHub yet. They were checked with actionlint and by running their
commands locally.

## What a release contains

| Artifact | Platform | Signature |
|---|---|---|
| `ScrapeLens_<version>_<arch>.deb` and `ScrapeLens_<version>_<arch>.AppImage` | Linux, x86_64 and arm64 | none; SHA-256 and attestation |
| `scrapelens-linux-<arch>` | Linux, standalone executable | none |
| `ScrapeLens-<version>-macos-arm64.zip` (`ScrapeLens.app`) | macOS arm64 | ad-hoc in CI; not Developer ID; not notarized |

The version is the same in `src-tauri/tauri.conf.json`, `src-tauri/Cargo.toml` and `app/package.json`.

The App's executable also runs the MCP server: `scrapelens mcp --sessions-dir <dir>` (the same code as
`scrapelens-mcp`, the same version and hardening). The packages carry it: `Contents/MacOS/scrapelens` in
the `.app`, `/usr/bin/scrapelens` in the `.deb`, and the AppImage's `AppRun`, which runs
`usr/bin/scrapelens`. How a client is configured is in the README, section "Configuring an MCP client".

Release binaries are built without the `test-hooks` feature, so the test-only variables and
command-line actions are not in them (see [TEST-HOOKS.md](TEST-HOOKS.md)). The check below prints
any test variable found in a binary; it must print nothing:

```sh
for v in SCRAPELENS_TEST_MODE SCRAPELENS_CAPTURE_HEADLESS SCRAPELENS_CAPTURE_IGNORE_CERT \
         SCRAPELENS_CAPTURE_NETWORK SCRAPELENS_CAPTURE_URL SCRAPELENS_TEST_PROXY_BYPASS_LOOPBACK \
         SCRAPELENS_TEST_PROXY_CA SCRAPELENS_CDP_TRANSPORT SCRAPELENS_RELAY_PEER_PROBE; do
  grep -a -q "$v" path/to/binary && echo "test-only variable in the binary: $v"
done
```

## macOS: build the app locally

Requirements: Rust 1.98.1, Node 26.8.1 and the Xcode command line tools.

```sh
cd app && npm ci && cd ..
./app/node_modules/.bin/tauri build --bundles app
```

The bundle is `target/release/bundle/macos/ScrapeLens.app` (root workspace target).

`tauri.conf.json` names the signing identity `ScrapeLens Local Signing`. That is a self-signed
certificate in the developer's login keychain, not a Developer ID. It keeps the designated
requirement stable across builds, so macOS permissions stay valid. Create it once with the procedure
in [Local signing identity](#local-signing-identity). Without that identity, build with an ad-hoc
signature instead:

```sh
./app/node_modules/.bin/tauri build --bundles app --config '{"bundle":{"macOS":{"signingIdentity":"-"}}}'
```

Checks, then the archive (keep it outside the repository):

```sh
app=target/release/bundle/macos/ScrapeLens.app
codesign --verify --deep --strict "$app"
codesign -dr - "$app"                       # designated requirement
ditto -c -k --keepParent "$app" ScrapeLens-<version>-macos-arm64.zip
```

### Local signing identity

| Item | Value |
|---|---|
| Name / common name | `ScrapeLens Local Signing` |
| Keychain | login (`~/Library/Keychains/login.keychain-db`) |
| Designated requirement | `identifier "app.scrapelens.desktop" and certificate root = H"d0a53befa59a447043abc9e58a3381addbbf1751"` |

The certificate root is the fingerprint of the identity the earlier releases were signed with. A new
identity changes it, and the change must be recorded in [PACKAGING-HISTORY.md](PACKAGING-HISTORY.md).

To create the identity (new machine or clean keychain). The private key is never committed and the
temporary files are removed:

```sh
TMP=$(mktemp -d)
cat > "$TMP/codesign.cnf" <<'EOF'
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_codesign
prompt = no
[req_distinguished_name]
CN = ScrapeLens Local Signing
O = ScrapeLens Local
C = BR
[v3_codesign]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
subjectKeyIdentifier = hash
EOF
openssl req -new -x509 -days 3650 -nodes -newkey rsa:2048 \
  -keyout "$TMP/scrapelens.key" -out "$TMP/scrapelens.crt" -config "$TMP/codesign.cnf"
P12PASS=$(openssl rand -base64 24)
openssl pkcs12 -export -inkey "$TMP/scrapelens.key" -in "$TMP/scrapelens.crt" \
  -out "$TMP/scrapelens.p12" -name "ScrapeLens Local Signing" -passout "pass:${P12PASS}"
security import "$TMP/scrapelens.p12" -k ~/Library/Keychains/login.keychain-db \
  -f pkcs12 -P "$P12PASS" -T /usr/bin/codesign -T /usr/bin/security
unset P12PASS
security add-trusted-cert -r trustRoot -p codeSign \
  -k ~/Library/Keychains/login.keychain-db "$TMP/scrapelens.crt"
# Optional (asks for the login keychain password if the session is not unlocked):
# security set-key-partition-list -S apple-tool:,apple:,codesign: -s \
#   -D "ScrapeLens Local Signing" -t private ~/Library/Keychains/login.keychain-db
rm -f "$TMP/scrapelens.key" "$TMP/scrapelens.p12" "$TMP/scrapelens.crt" "$TMP/codesign.cnf"
rmdir "$TMP"
security find-identity -v -p codesigning   # should list "ScrapeLens Local Signing"
```

If `security import` or `set-key-partition-list` asks for the keychain password, run the command in
Terminal. Do not save the password to a file or paste it into a chat.

## Linux: build the packages locally

The Linux packages are built inside a container, so nothing is installed on the host.
[`linux/Dockerfile`](linux/Dockerfile) pins the base image by digest (Ubuntu 22.04), Rust 1.98.1 and
Node 26.8.1 (checked against the official `SHASUMS256.txt`), and uses the lockfiles (`cargo --locked`,
`npm ci`). [`linux/build.sh`](linux/build.sh) runs the tests, clippy, the App's tests and typecheck,
`tauri build --bundles deb,appimage`, and the smoke test.

```sh
# at the repository root; ARCH is amd64 or arm64 (native on an arm64 host, emulated otherwise)
docker build --platform linux/$ARCH -f src-tauri/linux/Dockerfile -t scrapelens-linux:$ARCH .
docker run --rm --platform linux/$ARCH -v "$PWD/src-tauri/linux/out:/out" scrapelens-linux:$ARCH
```

The output is `src-tauri/linux/out/$ARCH/`: the `.deb`, the AppImage, `scrapelens`, `SHA256SUMS`,
`build.log` and `smoke.log`. Check it with `sha256sum -c SHA256SUMS` inside that folder. These
outputs are not in git.

The smoke test builds a test binary, `scrapelens-smoke`, with `--features test-hooks,tauri/custom-protocol`
after `npm run build`. It imports a HAR through the test command line under Xvfb and checks that a
session is written. A plain `cargo build --features test-hooks` lacks `custom-protocol`: the window then
loads the development server instead of the bundled frontend, and the import never writes a session.
`scrapelens-smoke` is a test artifact and is never shipped.

The browsers the App accepts on Linux are listed in [`linux/BROWSERS.md`](linux/BROWSERS.md).

## Limitations

- No Developer ID signature and no notarization; the project does not plan either. Gatekeeper may
  block the macOS app when it is downloaded from a release; the README explains how to open it.
- The Linux packages are not signed.
- macOS arm64 only. Intel is neither built nor tested.
- The save-panel flow of the macOS app is not covered by automated tests.
- The CDP endpoint starts with `--remote-allow-origins=*` (see [`capture/src/lib.rs`](../capture/src/lib.rs)).
  The exposure is limited to loopback, an ephemeral port and the capture window.
