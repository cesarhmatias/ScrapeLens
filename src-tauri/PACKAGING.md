# Packaging — final validated bundle

Status of the package delivered in this round. It serves as reproducible evidence:
the commands below produce exactly the artifact described, on the same machine and
under the same conditions.

## macOS — release bundle, English (2026-11-05, current)

Bundle built from the clean tree at `8c999aa` (provisional commit; it will be
remapped when the history is rewritten). It includes the core, capture and recon
changes after `f6f5282`, `2ac129b` and `a32cbd1`.

Bundle: `src-tauri/target/release/bundle/macos/ScrapeLens.app`.
SHA-256 of `Contents/MacOS/scrapelens` (18,268,880 bytes):
`aca3840f4620f4cddca7821a2a2c55e6082a5ab0e62c014975ecc0b8a6709883`.
Release archive: `/tmp/sl-release-en/macos/ScrapeLens-0.1.0-macos-arm64.zip`
(6,147,181 bytes, `ditto -c -k --keepParent`), SHA-256
`e687241b86e231a78c37c86d2ac3a54e08463243ace0bedc72213b2e9ff712a0`. Extracted
from the zip, the app still passes `codesign --verify --deep --strict`.
Signed with `ScrapeLens Local Signing`; designated requirement certificate root
`d0a53befa59a447043abc9e58a3381addbbf1751`.
Built with `./app/node_modules/.bin/tauri build --bundles app`. No window was opened
or activated, and the running ScrapeLens instance was not closed.
Validation: `cargo test` 60 passed, 0 failed, 8 ignored; `npm --prefix app test`
(seven suites), typecheck and build passed.

## macOS — English demo data (2026-11-05, previous)

Bundle built from the clean tree at `a7d8519` (provisional commit; it will be
remapped when the history is rewritten, so do not treat it as final). The synthetic
demo data embedded in the binary (`src-tauri/demo/session.json`) is now in English:
domains stay `.invalid` (`demo-shop.invalid`), and the paths, fields, ids, headers
and bodies are translated. Structure, statuses, durations and counts are unchanged;
the only structural change is the cart POST body, 32 bytes instead of 34.
Screenshots `01`–`15` were regenerated from this build's UI and checked one by one.
Screenshots `16`–`24` were removed earlier and are not part of the package.
SHA-256 of `Contents/MacOS/scrapelens` (18,268,880 bytes):
`46cd37efe468330ded3a98f401f4e3f21666fd7361b7034977b8f395a9c97b32`.
Signed with `ScrapeLens Local Signing`; `codesign --verify --deep --strict` passed;
designated requirement certificate root `d0a53befa59a447043abc9e58a3381addbbf1751`.
Built with `./app/node_modules/.bin/tauri build --bundles app`. No window was opened
or activated, and the running ScrapeLens instance was not closed.
Validation: `npm --prefix app test` (seven suites), typecheck and build passed;
`cargo test` 60 passed, 0 failed, 8 ignored; `cargo clippy --all-targets -- -D warnings`
passed.

## macOS — English interface (2026-11-05, previous)

Bundle built with the English UI from the clean tree at `4445160` (provisional
commit; it will be remapped when the history is rewritten, so do not treat it as
final). Screenshots `01`–`13` and `15` were regenerated in English. The app code
keeps the optional full export described below.

Bundle: `src-tauri/target/release/bundle/macos/ScrapeLens.app` (18.14 MiB).
SHA-256 of `Contents/MacOS/scrapelens` (18,268,880 bytes):
`9a358d3a7969348e1e5fd3c5803553282425909f9061a7fa9dc26a079121c8f2`.
Signed with `ScrapeLens Local Signing`; `codesign --verify --deep --strict`
passed; designated requirement certificate root
`d0a53befa59a447043abc9e58a3381addbbf1751` (same as the previous build).
Built with `./app/node_modules/.bin/tauri build --bundles app`. No window was
opened or activated, and the running ScrapeLens instance was not closed.

Validation: `npm --prefix app test` (seven suites) passed; `npm --prefix app run
typecheck` passed; `npm --prefix app run build` passed. `cargo test` on this tree:
60 passed, 0 failed, 8 ignored; `cargo clippy --all-targets -- -D warnings` clean.

## macOS — optional full export (2026-11-04, previous)

App code: `71d9f7c`. The **Export / Sanitize…** dialog keeps the sanitized copy
by default. The **Include sensitive data** checkbox enables the full capture
(session, attachments and the artifacts present `cdp-events.jsonl`, `netlog.json`,
`cdp-bodies.jsonl`), without redactions, with a highlighted warning and suggested
destination `-full`. The destination remains subject to the same refusals: source,
internal folder, symlinks or an occupied folder. Special raw files/symlinks are
refused; copy is streamed with `O_NOFOLLOW`, files 0600 and directory 0700.
Nothing from the source is changed.

Bundle: `src-tauri/target/release/bundle/macos/ScrapeLens.app`.
SHA-256 of `Contents/MacOS/scrapelens` (18,268,880 bytes):
`bd8d10a6b753287ad85235c7a48a3b6a3659f612d7e9e2b08cc55feb40fd5d71`.
Signed with `ScrapeLens Local Signing`; `codesign --verify --deep --strict`
passed and DR preserved (`d0a53befa59a447043abc9e58a3381addbbf1751`).
No window opened or activated. Linux not rebuilt in this task.

Validation: `cargo test --locked` 60 passed, 0 failed, 8 ignored;
clippy `--locked --all-targets -- -D warnings` clean; `npm test` (seven suites),
typecheck and build passed. Rust tests preserve the fixtures' secrets in
cookies/bodies/artifacts, and verify permissions and destination/symlink refusals.
`app/src/Export.test.tsx` exercises the checkbox, preview and save calls with
`includeSensitive=true`, switching of the suggested destination, and preservation
of an edited path. React component test, without automating the native dialog.
Logs: `/tmp/sl-full-{rust,clippy,front,bundle}.log`.

## macOS — browser cookie selector (current)

Source: `3e09738`, on top of `2a52152`, clean tree before the build.
The **Cookies** selector next to Start URL lists the detected profiles and saves
only the identifier in private preferences. A removed source falls back to a clean
session; an invalid source passed to the command is refused. With an empty URL,
the capture ignores the source and the UI warns to enter the start URL.
The DTO does not expose the database path. Cookies flow into `CaptureConfig` and
are imported by the capture crate before navigating; failures are shown by the
capture start warning.

Bundle: `src-tauri/target/release/bundle/macos/ScrapeLens.app`.
Internal executable `Contents/MacOS/scrapelens`: **18,277,584 bytes**,
SHA-256 `9645c147f2f43b3286421d94e7e0a39376b2add404f0e22b0502fe0bff8a80c8`.
The hash identifies the executable, not the `.app` directory.
Signature `ScrapeLens Local Signing`; `codesign --verify --deep --strict`
passed; DR preserved (`d0a53befa59a447043abc9e58a3381addbbf1751`).
Bundle ready for the user to open; no windows opened or activated in this run.
The existing instance was not terminated or replaced while running.

Validation: `cargo test --locked` **58 passed, 0 failed, 8 ignored**;
`cargo clippy --locked --all-targets -- -D warnings` clean; six front suites
(`test:cookie-source`, `test:shortcuts`, `test:adapter`, `test:capture-url`,
`test:paged`, `test:list-view`), typecheck and build passed. New tests cover legacy
preferences/persistence, ID validation, absence of the database path in the DTO,
and the selector markup (saved choice, clean session, blocking and URL hint).
No real import of personal cookies and no GUI test of the selector were performed.
Linux was not rebuilt in this task; the packages below remain at `22854c3`.
Logs: `/tmp/sl-cookie-rust.log`, `/tmp/sl-cookie-validation.log`,
`/tmp/sl-cookie-validation.json` and `/tmp/sl-cookie-bundle.log`.

## Release round 16 — 2026-11-03 (current)

This section replaces the hashes and source of the earlier rounds below.
Source: `22854c3` (clean tree before the builds), including `f377617`
(Capture FIFO/wrappers validation) and `ad4f5c1` (NetLog parser streamed, P4), with
clippy/Core closure and duplicated `events` semantics in `22854c3`.
Builds run to completion in this turn, with no callback, without opening or
activating macOS windows, without touching the VMs and without a push.

| Artifact (relative to the root) | Bytes | SHA-256 |
|---|---:|---|
| `src-tauri/target/release/bundle/macos/ScrapeLens.app/Contents/MacOS/scrapelens` | 18089024 | `cbebd19d9c2339774fb6e959ae136439c896d69efd747f4bdf53d07f4c9ccf3f` |
| `src-tauri/linux/out/amd64/ScrapeLens_0.1.0_amd64.deb` | 6404930 | `871a04eb10e79ca291de16ca113a60dc766c733f84fad98a6ec8cdc6c479be15` |
| `src-tauri/linux/out/amd64/ScrapeLens_0.1.0_amd64.AppImage` | 84404728 | `d06c7d80d5bcb99d648944571cb704e72c71d11356b18eb1160c7721bb47039c` |
| `src-tauri/linux/out/amd64/scrapelens` | 21938000 | `6d9007aa510787e3376c3c3e3a400abff903ac3716c9bf04bbe803834ae815fd` |
| `src-tauri/linux/out/arm64/ScrapeLens_0.1.0_arm64.deb` | 6504416 | `11161abc54774b9ce94f7d140645c0120c24f76b4f27d12bdc2db33e1571a410` |
| `src-tauri/linux/out/arm64/ScrapeLens_0.1.0_aarch64.AppImage` | 82569736 | `5fb8f9138ef3dd65cb3af26a08f0a4801381de4b37729f8331df1502aa76aef6` |
| `src-tauri/linux/out/arm64/scrapelens` | 20702552 | `f9e0ecf0d2ffeafbee2ed69e5678d4eac1fa85841b09c18c246fed543b2116d5` |

macOS arm64: `cargo test --locked` **56 passed, 0 failed, 8 ignored**;
`cargo clippy --locked --all-targets -- -D warnings`, five front tests
(`test:shortcuts`, `test:list-view`, `test:paged`, `test:capture-url`,
`test:adapter`), typecheck and Vite build passed. Bundle signed with
`ScrapeLens Local Signing`; `codesign --verify --deep --strict` passed.
DR preserved: `identifier "app.scrapelens.desktop" and certificate root =
H"d0a53befa59a447043abc9e58a3381addbbf1751"`.
The macOS hash identifies the executable inside the `.app`, not the directory.
No macOS GUI smoke test was run in this round.

Linux amd64 (emulated) and arm64 (native) via Docker/Ubuntu 22.04:
`cargo test --locked` **56 passed, 0 failed, 8 ignored** on each architecture;
clippy with `-D warnings`, the same five front tests and typecheck passed;
`.deb` and AppImage generated. Xvfb smoke with `SCRAPELENS_TEST_MODE=1 --import-har`
wrote `session.json` with **1 request** on each architecture and terminated the
executable by SIGTERM. The smoke uses the standalone executable: it does not run the
AppImage nor test installation of the packages or shortcuts via X11. There was no
new validation on Ubuntu 24.04/Debian 12. No Linux signature; verify with
`sha256sum -c SHA256SUMS` in the respective output directory.
The recipe pins toolchains/lockfiles, but does not promise bit-for-bit reproduction.

Evidence: `/tmp/sl-r16-{macos,amd64,arm64}.log`,
`/tmp/sl-r16-result.json`, `/tmp/sl-r16-final-hashes.json` and
`src-tauri/linux/out/{amd64,arm64}/{build.log,smoke.log,SHA256SUMS}`.

The first amd64 `docker run` failed with a missing parent snapshot in the daemon;
rerunning the same command completed with exit code 0. Log of the successful attempt:
`/tmp/sl-r16-amd64-retry.log` (the script's JSON keeps `run=125` from the first attempt).

## Build sources

| Item | Value |
|---|---|
| Repository | `/Users/cesar/Projects/scrapelens` |
| App commit at build time | `f81ea80` (clean HEAD; round 13 wave 1 + P5 paginated + addendum 9; `f81ea80` only adds the `list_requests` log to stderr under `SCRAPELENS_TEST_MODE=1`, used as evidence) + local identity `ScrapeLens Local Signing` |
| Export commits included | `eaf5471` (Tauri shell), `0a6e696` (UI), `0446f18`/`12457cd` (formatting), `3a3c676` (preview adjustment) |
| Round contract | `4c97bc9` (`docs/07-ui-export.md`); multi-target `docs/14-multi-target-capture.md` + UI `9a06463` |
| Core | path `scrapelens-core`; `3fe7efc` (A9-B1/A9-B2) with P1/P2/P3/P6/P7 (streamed validation, index-based correlation, compact `session.json`, `sanitize_bundle_owned`) |
| Capture | crate `capture/`; descriptor-based writing in `capture/src/fdio.rs`; CDP over pipe; `SCRAPELENS_CDP_TRANSPORT=port` returns to the old mode (`737290a`) |
| Build date | 2026-11-02 (UTC−03) |
| Working tree | clean HEAD `f81ea80`; `src-tauri/Cargo.lock` unchanged; `SCRAPELENS_TEST_MODE=1 --open-capture tests/capture/runs/20261027T0730Z/session-har` filled the list through the paginated contract (`list_requests offset=0 items=15 matched=15 total=15`); `--open-capture /private/tmp/big20k` paginated 20,002 requests in 11 pages of 2,000 |

There is no sidecar, helper process or Node/Python runtime in the product.

## Commands run

```sh
# at the repository root
cd app && npm install                     # once
cd ../app && npx tsc --noEmit             # frontend typecheck — no output
cd ../app && npm run build                # Vite bundle — 590,75 kB (gzip 123,89 kB)
cd ../app && npm run test:paged           # paginated contract (list + detail)
cd ../core && cargo test                  # ok (358 passed, 0 failed, 1 ignored)
cd ../src-tauri && cargo test             # 55 passed, 8 ignored; 0 failed
cd ../src-tauri && cargo clippy --all-targets
cd .. && ./app/node_modules/.bin/tauri build --bundles app
# tauri.conf.json → bundle.macOS.signingIdentity = "ScrapeLens Local Signing"
# (Tauri signs by itself; equivalent manual re-sign:)
cd src-tauri/target/release/bundle/macos
codesign --force --deep --options runtime --sign "ScrapeLens Local Signing" ScrapeLens.app
codesign --verify --deep --strict ScrapeLens.app
codesign -dr - ScrapeLens.app   # stable DR: certificate root, not cdhash
```

Tools used: rustc 1.99.0, Node 26.8.1, macOS 26.5.2 (arm64).

## Local code signing identity

**Not a Developer ID.** It is not for distribution, Gatekeeper or notarization.
It is only a self-signed certificate in the developer's login keychain, so that the
bundle's designated requirement cites the certificate (stable across builds) instead
of the ad-hoc cdhash (which changes on every re-sign and breaks TCC / App Management).

| Item | Value |
|---|---|
| Name / CN | `ScrapeLens Local Signing` |
| Keychain | login (`~/Library/Keychains/login.keychain-db`) |
| Designated requirement | `identifier "app.scrapelens.desktop" and certificate root = H"d0a53befa59a447043abc9e58a3381addbbf1751"` |
| Stability | same across two consecutive `tauri build` runs (verified) |

### How to recreate (new machine / clean keychain)

Temporary files only in `/tmp`; delete the key and the `.p12` after import.
Never commit the private key.

```sh
TMP=$(mktemp -d /tmp/scrapelens-codesign.XXXXXX)
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

If `security import` or `set-key-partition-list` asks for the Keychain password, run the
command in Terminal (do not save the password to a file or in the chat).

## Artifact

| Item | Value |
|---|---|
| Bundle | `src-tauri/target/release/bundle/macos/ScrapeLens.app` |
| Executable | `ScrapeLens.app/Contents/MacOS/scrapelens` |
| Architecture | `Mach-O 64-bit executable arm64`, thin (no universal binary) |
| Bundle size | 18,332 KiB (`du -sk`) |
| Executable size | 18,015,088 bytes |
| Executable SHA-256 | `fcdc4bd26a71a4e31e5366d7e2b881e0c5cd63911589186d70db17068ad4acde` |
| Identifier | `app.scrapelens.desktop` |
| Signature | `ScrapeLens Local Signing` (`flags=0x10000(runtime)`, `TeamIdentifier=not set`) — **not** Developer ID |
| Designated requirement | `identifier "app.scrapelens.desktop" and certificate root = H"d0a53befa59a447043abc9e58a3381addbbf1751"` |
| `codesign --verify --deep --strict` | exit 0 (valid on disk, satisfies the Designated Requirement) |
| `spctl -a` | rejected — expected: no Developer ID and no notarization |

Round 13 D7 clean rebuild HEAD `885b592` (2026-11-03; Capture `e8ae66c`/`885b592` suppresses the automation warning in every capture; opened and closed once with `open -g`, without activating the window; SHA `fcdc4bd2…` replaces `78155379…`). Before: round 13 wave 2 clean rebuild HEAD `291fae4` (2026-11-02; network open in capture with `SCRAPELENS_CAPTURE_NETWORK=loopback` for tests only (Capture `3dda266`), on-demand paginated list (`6f11440`), demo without empty chips and recording badge only on the recorded session (`f00a2e4`), no internal decorative window (`312c891`), clippy `-D warnings` clean; SHA `78155379…` replaces `52cd14fd…`). Before: round 13 wave 1 clean rebuild HEAD `f81ea80` (2026-11-02; paginated contract P5, open/import/shutdown moved off the main thread, `starting` state, session by name with any name; SHA `52cd14fd…` replaces `2691f152…`). Before: round 12 addendum 8 clean rebuild HEAD `ce68eb9` (2026-11-02; test CLI requires `SCRAPELENS_TEST_MODE=1`; SHA `2691f152…` replaces `405b77fa…`). Before: round 12 wave 1 clean rebuild HEAD `737290a` (2026-11-02; CLI test mode verified in the bundle; SHA `405b77fa…` replaces `f3039e58…`). Before: round 12 clean rebuild HEAD `fc5ca18` (2026-11-01; Core `73e457d`/`fc5ca18` completeness + sessionSetup; SHA `f3039e58…` replaces `65a6529c…`). Before: round 11 clean rebuild HEAD `1f7d7d5` (2026-11-01; core without rustix; SHA `65a6529c…` replaces the invalid `d30af7f4…`). Before: round 11 clean rebuild (HEAD `517b949`, `core/` = `868127b`, 2026-11-01; SHA `d30af7f4…` replaces `39f1233d…`, generated with a dirty tree). Before: round 11 capture+core rebuild `0b94424`/`39826a3`/`93361b8`/`e6fc955`/`868127b` (source HEAD `868127b`, 2026-11-01; rustix in core; SHA `39f1233d…`; previous hash `114614c2…`). Before: round 11 capture+core rebuild `daa3414`/`e6a9edd`/`952921a`/`d50a19f` (source HEAD `d50a19f`, 2026-10-31; SHA `114614c2…`; previous hash `57264aed…`). Before: round 11 capture rebuild `23bcba6`/`0997a3b` (source HEAD `d8ad643`, 2026-10-31; SHA `57264aed…`; previous hash `8558470b…`). Before: round 11 capture rebuild `62afa63` (source HEAD `61ad875`, 2026-10-31; SHA `8558470b…`; previous hash `4636a3cf…`). Before: round 11 capture rebuild (source HEAD `03ee85c`, 2026-10-31; Chrome codesign `--deep`, NetLog in profile, CLOEXEC, navigate deadline; SHA `4636a3cf…`; previous hash `6c0092c3…`). Before: round 11 (source HEAD `eb66afa`, 2026-10-31; capture in `capture/`; CDP over pipe by default, `SCRAPELENS_CDP_TRANSPORT=port` for the old mode; SHA `6c0092c3…`; previous hash `1901f3b4…`). Before: round 10 stable signing (source HEAD 0ddd387, 2026-10-31; local cert `ScrapeLens Local Signing`; DR by certificate root, stable across 2 builds; previous hash `b3e12edc…`). Before: round 10 orphan cleanup (source HEAD 8fd4f6d, 2026-10-31; Tauri setup calls `capture::cleanup_orphans` in a thread; test `startup_removes_orphan_capture_with_dead_owner`; previous hash `7a46fa4c…`). Before: round 10 definitive (source HEAD 66e97e3, 2026-10-31; UI `target.notes` + `cdp.target_setup_error`/`timeout` in Limits; capture `/multi/` with "not confirmed" on sw-intercept and Limits without setup warning; screenshot 44; previous hash `02e6ef30…`). Before: round 10 final (source HEAD 8cfe828, 2026-10-30; Capture 1716d39–8cfe828 + Core df421cf/7892303; SW without copies in the list, sw-intercept enabled as ambiguous, Limits without a false "did not attach"; old session without sessionId and without the Target column; screenshots 42/44/47; previous hash `77cf7355…`). Before: round 10 (source HEAD 881fa0d, 2026-10-30; bundle with multi-target capture d60c1ae+, UI Target `9a06463`, Tests acceptance; live capture `/multi/` via the `.app` with Target column and target filter; evidence `evidence/bodies-search/46-multi-target-bundle.png`; previous hash `d1136cbb…`). Before: round 9, wave B, 3rd time (source HEAD 7410fa4, 2026-10-29; bundle with `plan.parameters` exempt only with a verified plan — current version, hash and target checked; core-only fix, traces and screen unchanged; previous hash `a4fe000a…`). Before: round 9, wave B, 2nd time (source HEAD 39410bf, 2026-10-29; bundle rebuilt with the `parameters` exemption restricted to the (name, part) pair of the plan — core-only fix, traces and screen unchanged; previous hash `860c2008…`). Before: round 9, wave B (source HEAD 31bcaa9, 2026-10-29; plan.version 2 in the trace, traces ok/403/incomplete regenerated against detran-sim and validation with no spurious warnings on the faithful trace; includes cleanup_on_start from 4a81cb0 and plan.parameters from d83d620; previous hash `bdce5796…`). Before: round 9, 3rd time (source HEAD a37cd60, 2026-10-29; trace temporary with keep/discard, 64 MiB limit, new validate verdicts with core plan.hash; previous hash `0b49ba0c…`). Before: round 9, 2nd time (source HEAD 2a5c533, 2026-10-29; validate with adapter and class "user parameter"; previous hash `48e1ab6d…`). Before: round 9 (source HEAD 744df02, 2026-10-29; timeline, "Validate execution…" with import-trace into a new folder and validate; previous hash `bda06a2d…`). Before: final build closing round 8 (source HEAD dc14ac3, 2026-10-29; strict as default for adapter parts; advanced option "lenient parts" (`lenient_parts`) in the priming script, off by default; previous hash `0eb5632a…`). Before: final build of round 8, 2nd time (source HEAD c07b514, 2026-10-29; includes b4511fb and c07b514 from Capture; previous hash `bee5f6d6…`). Before: final build of round 8 (source HEAD 5d2c6e6, 2026-10-29; includes 391db16, 5d2c6e6 from Capture, 3ba9486 from Core and the adapter view's part cut; previous hash `53009655…`). Before: final rebuild of round 8 (source HEAD b0ce0f0, 2026-10-29; includes Capture grammar limits, core c61d407 and the adapter view's per-field limit; previous hash `9aec2199…`). Before: round 8 rebuild (source HEAD aab8559, 2026-10-29; `natural-ajax` adapter via path dependency in origins/chain/compare/priming, structured view and "Priming script" tab; previous hash `6e301e70…`). Before: final rebuild (source HEAD 4b16b0e, 2026-10-29; includes cf015b2 CDP initiator and 6a85676 priming detectors; previous hash `1a097cd0…`). Before: rebuild 7e (reading `assess-rules.json` only as a regular file without symlink, up to 256 KiB, parse error without echo; previous hash `56514c8b…`). Before: rebuild 7d (`AssessRules::warnings()` warnings returned by `assess_session` and shown in the list and in the Application tab; previous hash `0dba0476…`). Before: rebuild 7c (separate filters "Application failures" = app-error and "Possible blocks?" = blocked?, combinable; previous hash `aa066f1a…`). Before: rebuild 7b-2 (assess `counts` with `VerdictKind::count_key()`, kebab-case keys equal to `verdictKind`; previous hash `83d67718…`). Before: rebuild of the 7b adjustment (verdict `not-assessed` neutral; previous hash `0f6d04bf…`). Before: rebuild of wave 7b (command `assess_session`, column/filter/"Application" tab, verdict in the chain and in compare; previous hash `4f7ca2aa…`). Before: rebuild with auxiliary frames and initiator (previous hash `1697321d…`). Before: rebuild of wave 6b (HTML control, static context, context pages, HAR warnings without cookies, compare by rounds with options, business sanitization; previous hash `f777988f…`). Before: rebuild of the reorder hint tied to `SessionComparison.reordered` (previous hash `21824159…`). Before: rebuild of the compare layout adjustment (chips wrap lines; optional reorder hint); previous hash `ac7213b2…`. Before: rebuild with core labels (possible origin) and regenerated fixtures; previous hash `31ec27c3…`. Before: rebuild of round 5 review fixes (possible origin, confidence per step, paginated comparison, canonical paths, partsCounts; previous hash `c1783a57…`). Before: rebuild of wave 5b (Origin tab, priming chain, A × B comparison, export with annotated origins; previous hash `2f08150d…`). Before: rebuild of round 4 polish (highlight legend only when there is a dashed line, discreet note for `chrome-decoded`, warning for `charset:*`/`lossy-postData`); previous hash `0e2754f4…`. Before: rebuild with core lazy search (LazySession + search_lazy), solid/dashed highlighting and synthetic fixture text; previous hash `f9c0acec…`. Before: rebuild of round 4b review fixes (origin labels, highlight by core range, search bundle cache, symlink refusal in attachments, `transformed`; previous hash `56ee754b…`). Before: rebuild of wave 4b (search in payload and bodies panel: commands `search_session` and `read_body`, UI; 28+2 ignored in src-tauri, 16/16 in tests/export, `npm run test:adapter` ok; evidence in `evidence/bodies-search/`). Previous hash `9c04b98b…` replaced. History: rebuild of 0d4dbab (`fix(app)`: adapter tolerates fields omitted that core accepts via serde default; test `npm run test:adapter` with the minimal fixture; 15+1 ignored Tauri, 16/16 regressions in tests/export). Previous hash `5934556c…` (16015a1) replaced. Before: rebuild with validation of all ancestors of the destination (F1/F2): the hash above is from this build. The SHA-256 is of the executable **after** the ad-hoc re-sign. A clean `tauri build`
produces a byte-different binary (the linker signs before the bundle), so the hash identifies this artifact, not the output of any build. The previous build of this same round, without the `3a3c676` adjustment, had
`ee127a56fa51a1403616dc4cb3796afd3bb5ec4d595c6da699c0cac1a16d9344`; it was replaced by this one.

## Execution validation

- Bundle launched by the automation driver (`app.scrapelens.desktop`), single window
  1440×920, no telemetry.
- `cargo test` in `src-tauri` covers the export bridge: cURL/Python preview, quote
  escaping, `captured` vs `unavailable` body, overwrite refusal, symbolic-link refusal,
  and the source left intact after sanitizing.
- `cargo test` in `core` covers the exporters and sanitization used here; there were
  no changes to core in this round.

### Paginated contract in the bundle (round 13)

- `SCRAPELENS_TEST_MODE=1 ScrapeLens.app/Contents/MacOS/scrapelens --open-capture
  tests/capture/runs/20261027T0730Z/session-har` → stderr with
  `list_requests offset=0 items=15 matched=15 total=15`; window closed by SIGTERM.
  The log exists only in test mode; the list came through the new contract, not from
  the whole `session.json` in the front end.
- `--open-capture /private/tmp/big20k` (session of 20,002 requests) → 11 pages of
  2,000 + 2 final, `matched=20002 total=20002`. RSS of the `WebKit.WebContent` process
  on open: **181,488 KiB (~177 MiB)**; main process **1,334,736 KiB (~1.27 GiB)**.
- The window must be active: with the app in the background, WebKit did not run the
  `list_requests` calls until activation (macOS throttling/App Nap).
  The measurement and list confirmation were done with the window active; without
  activation, the CLI opened the session but the list stayed pending. The front end
  also redid the full scan three times (33 calls) when mounting the screen.
- Wave 2 (HEAD `291fae4`, bundle `78155379…`): the same opening of
  `/private/tmp/big20k` with the window activated (via `System Events`, no click) made
  **2** `list_requests` calls until the first screen (`offset=0` and `offset=2000`,
  visible page + 1 spare, `matched=20002`), versus 33 in wave 1. The window still
  needs to be active.
- `/tmp/big20k` is not accepted as a path: `/tmp` is a symlink to `/private/tmp` and
  the CLI refuses symlinks in any component (expected behavior, A8-B6).

## Linux (round 14)

Build in a container, with nothing installed on macOS: `src-tauri/linux/Dockerfile`
(Ubuntu 22.04 pinned by digest `sha256:076e7bf8…5e11`, Rust 1.98.1, Node 26.8.1
checked against the official `SHASUMS256.txt`, `cargo --locked` and `npm ci`) and
`src-tauri/linux/build.sh` (tests, `tauri build --bundles deb,appimage`, Xvfb smoke).

```bash
# at the repository root; ARCH=amd64 (emulated in OrbStack) or arm64 (native)
docker build --platform linux/$ARCH -f src-tauri/linux/Dockerfile -t scrapelens-linux:$ARCH .
docker run --rm --platform linux/$ARCH -v "$PWD/src-tauri/linux/out:/out" scrapelens-linux:$ARCH
# output: src-tauri/linux/out/$ARCH/{*.deb,*.AppImage,scrapelens,SHA256SUMS,build.log,smoke.log}
```

Artifacts in `src-tauri/linux/out/` are kept out of git (`.gitignore`).

| Artifact (source HEAD `98ab629`, clean tree, Linux shortcuts fixed and `capture/` port included) | SHA-256 |
|---|---|
| `amd64/ScrapeLens_0.1.0_amd64.deb` | `5d288b32575bd8a12bb65f59178534cf4f34e447fd0ec3e5485ff35115df53ac` |
| `amd64/ScrapeLens_0.1.0_amd64.AppImage` | `64b08eb83747f4dec1205c7f99f83e5219d0e2c4df6119d474f4993e88c40ec5` |
| `amd64/scrapelens` (executable) | `cd606a5d08aae7de7ce98f05c9183cbd3d06a7c3edafed1bf944c6d1d7f9367b` |
| `arm64/ScrapeLens_0.1.0_arm64.deb` | `a43397f34591c707d6c4f34f2321bd7d67750572efedce4880a7879ef35fde09` |
| `arm64/ScrapeLens_0.1.0_aarch64.AppImage` | `7c291e0b0ba29508b3e157ccf5ef334ff3fb89f723d02f34de89fff0a40d66f1` |
| `arm64/scrapelens` (executable) | `fc667f779f0f017c4844f7994bf321500dc8cf21ded8a38f712f7d4dbf1debf3` |

No signature on Linux. To verify: `sha256sum -c SHA256SUMS` in the artifact's folder,
or `sha256sum ScrapeLens_0.1.0_amd64.deb` compared with the table above.
The build is **not bit-for-bit reproducible**: two consecutive arm64 builds produced
different hashes (the hash identifies the artifact, not the recipe). Toolchain and
dependencies are pinned; what varies is the generated content (build IDs, internal
timestamps).

Results in the containers (amd64 and arm64 identical): `cargo test` 56/0/8, clippy
`-D warnings` clean, `test:shortcuts`, `test:list-view`, `test:paged`, `test:capture-url`,
`test:adapter` and `tsc` ok; smoke with `SCRAPELENS_TEST_MODE=1 --import-har
fixtures/acceptance/headers-cookies/headers-cookies.har` under `xvfb-run` wrote
`~/.local/share/app.scrapelens.desktop/sessions/har-…/session.json` (1 request)
and the app was closed by SIGTERM. Both smokes emitted an AT-SPI warning about a missing
accessibility bus, without preventing the import or the listing. Evidence for this rebuild:
`/tmp/sl-shortcuts-{amd64,arm64}.log`, `/tmp/sl-shortcuts-result.json` and
`src-tauri/linux/out/{amd64,arm64}/{build.log,smoke.log,SHA256SUMS}`. There was no X11
test of the shortcuts nor reinstallation of these packages on the VMs in this run; the
shortcut validation here is automated in the front end. In the previous build (dirty tree),
the amd64 `.deb` installed with `apt install ./…deb` on
`ubuntu:24.04` and `debian:12`, with no missing library in `ldd`. The AppImage was not
run (it would need FUSE or `--appimage-extract-and-run`); 24.04/Debian 12
were installation-only, without opening the window.

Platform differences: shortcuts appear as `Ctrl+`/`Shift+` (the menu already uses
`CmdOrCtrl`); preferences in `$XDG_CONFIG_HOME/app.scrapelens.desktop` (0700/0600,
same atomic write); "Show in file manager" opens the folder with `xdg-open` (it does
not select the file). The Linux port of `capture/` is included. The capture, import,
demo and copy-URL shortcuts are also handled in `keydown` outside macOS (`98ab629`),
with the button state guards.

## Export/sanitization evidence

Folder: `src-tauri/evidence/export/`.

| File | Content |
|---|---|
| `command-output.txt` | real output (generated by the `export_dump` example, already removed from the repository): cURL/Python previews, sanitization preview and the saved result |
| `preview-curl.json`, `preview-python.json` | literal responses of `export::preview` (1317 and 1745 bytes of text) |
| `sanitize-preview.json`, `sanitize-saved.json` | 24 requests, 152 redactions (`cookie`, `header:cookie`, `header:set-cookie`, `setCookie`), suggested destination and result |
| `05`–`14-*.png` | app screens: demo, open session, detail, cURL dialog, Python dialog, cancel, saved file, sanitization, result and opened sanitized session |
| `ui-harness.mjs` | Playwright harness that exercises the React components |
| `ui-harness-result.json` | summary: copied and saved file identical to the Python preview (`copied_matches_python`, `saved_matches_python`) |
| `saved-har-0002.sh` | exact text that the save dialog handed to the command |
| `prepare-payloads.py` | recreates the large payloads used by the harness |

Session used: `~/Library/Application Support/app.scrapelens.desktop/sessions/har-3dbc391c02a985c5-2`
(24 requests, imported from synthetic HAR at `127.0.0.1:8781`). The reference
sanitized folder (0700/0600, `session.json` with 872,082 bytes) was generated in
`evidence/export/sanitized-har-synthetic/` and checked by searching for markers:
`fromjs`, `sc_a=alpha` and `sc_b=beta` do not appear in any sanitized file. It is
derived and therefore not in git; the `export_dump` example that generated it was
removed — recreate it with the app's sanitization command.

**What the harness proves and what it does not.** The harness serves the real `dist/`
of the front end, injects a `__TAURI_INTERNALS__` stub and uses the **real** responses
written by Rust; only the native dialogs, the clipboard and the file picker are
simulated. It proves the behavior of the React components (cURL/Python switching,
copied/saved text equal to the preview, cancel without writing, opening the sanitized
session). It does **not** prove the native macOS dialog nor the real file write by the
user; these paths are covered by the Rust tests (`write_text_file`, `sanitize_to`) and
by the bundle, but the manual pass through `NSSavePanel` was not automated in this round.

## Screenshots

| File | Content |
|---|---|
| `src-tauri/evidence/export/08-dialog-curl.png` | cURL preview with body state, warnings and a not-executed notice |
| `src-tauri/evidence/export/09-dialog-python.png` | same request in Python (`http.client`) |
| `src-tauri/evidence/export/10-dialog-cancel.png` | native dialog cancelled: nothing written |
| `src-tauri/evidence/export/11-dialog-saved.png` | saved file with path and bytes |
| `src-tauri/evidence/export/12-dialog-sanitize.png` | sanitization preview with redactions by source |
| `src-tauri/evidence/export/14-sanitized-session.png` | sanitized session opened in the app |

## Limitations this package keeps

- No Apple Developer ID signature and no notarization; distribution outside this
  machine requires `xattr -d com.apple.quarantine` or real signing/notarization.
- Only arm64 built and tested; Intel not validated.
- Multi-target capture: page, popup, `_blank`, OOPIF, worker and service worker;
  a `_blank` document may come only from the NetLog.
- Bodies coming from CDP stay `unavailable` (they are not downloaded); the UI shows the
  reason instead of inventing content. No session captured on this machine has a body;
  only the unit test covers the `captured` case.
- `--remote-allow-origins=*` on the CDP endpoint (see `src-tauri/src/capture.rs`);
  risk limited to loopback, the ephemeral port and the capture window.
- The manual save flow through `NSSavePanel` inside the bundle was not automated: the
  native macOS panel does not expose AX to the driver (`off_space_or_ax_unresolved`),
  and the foreground attempt hit another app.
  2-minute validation script: open `ScrapeLens.app`, `Open capture…` →
  `har-3dbc391c02a985c5-2`, open the `/setcookie` request, `Export…`, `Save…`, choose a
  new folder and check that the file is 0600; then `Sanitize…` and `Open sanitized session`.
