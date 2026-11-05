# 21. ScrapeLens Linux version (capture and recon)

Round 14, at the user's request. Scope of this stage: port `capture/` (and `recon/`, which
needed no change) to Linux **without regressing macOS**. The port of `capture/` did not
depend on the App: `src-tauri/` was not touched in this stage, but in the **round 14 acceptance**
it was packaged (`.deb` and `AppImage`, amd64 and arm64) and passed the real battery on the
OrbStack VMs (§7.1). The MCP server (`mcp/`) builds and passes its tests on Linux without changes.

## 1. Target and what was tested

Main target: Linux x86_64 (Ubuntu 22.04, Ubuntu 24.04, Debian 12), with the browser
**stable Google Chrome**. Secondary: arm64, where Google **does not publish** a Linux build of
stable Chrome: the accepted browser is **Chromium**, and this is recorded in the session.

Test environment: Docker via OrbStack on this machine (`linux/arm64` engine; `linux/amd64`
runs under emulation), images in `experiments/linux/`. Everything inside the container, on loopback,
with no real site; nothing was installed on the user's macOS.

### Scoreboard per platform

All rows ran with the **same code** (the working tree at this round's commit).
Each column is a command; `—` = not applicable.

| Platform | Browser | clippy `-D warnings` (capture, recon) | `cargo test --lib` (capture) | live on loopback (`--ignored`) | recon: `cargo test` + `live_e2e.sh` | `check_multi_target.py` | profile under `XDG_RUNTIME_DIR` | mcp |
|---|---|---|---|---|---|---|---|---|
| Ubuntu 24.04 amd64 | Google Chrome 156.0.8078.79 (`google-chrome-stable`) | ✓ | 96 passed | 17/17 | 27 + 3 passed | OK (16/16 NetLog, ≥15/16 CDP) | ✓ | ✓ |
| Ubuntu 22.04 amd64 | Google Chrome 156.0.8078.79 | ✓ | 96 passed | 17/17 | 27 + 3 passed | OK | ✓ | ✓ |
| Debian 12 amd64 | Google Chrome 156.0.8078.79 | ✓ | 96 passed | 17/17 | 27 + 3 passed | OK | ✓ | ✓ |
| Debian 12 **arm64** | **Chromium** 156.0.8078.73 (`chromium`) | ✓ | 96 passed | 17/17 | 27 + 3 passed | OK | ✓ | ✓ |
| macOS arm64 (this machine) | Google Chrome 156 | ✓ | 91 passed (the 5 fewer are the Linux-only tests) | 17/17 | 27 + 3 passed | OK | — | ✓ |

- The **17 live tests** include `navigator.webdriver === false` in the full and in the controlled capture,
  pipe and port, the 8 paths of the port gap, planted symlinks, swapping the session folder,
  message above the ceiling, a second CDP client and open network resolving a local name.
- Also with a window (**not headless**) under **Xvfb** (`SL_LIVE_HEADED=1`): the two captures that
  hide `navigator.webdriver` pass on Ubuntu 24.04 amd64 (Chrome) and on Debian 12 arm64
  (Chromium).
- The real browser of each image passes `validate_chrome` and returns product, version,
  binary and owning package: `GoogleChrome 156.0.8078.79 /opt/google/chrome/chrome
  package=Some("google-chrome-stable")` and `Chromium 156.0.8078.73 /usr/lib/chromium/chromium
  package=Some("chromium")`.


## 2. What changed in the code

| File | Change | macOS |
|---|---|---|
| `capture/src/chrome.rs` | Linux candidates; `validate_chrome_linux` (§3); `BrowserKind` (Chrome or Chromium, marked); `ValidatedChrome` gained `kind` and `package`; `Untrusted` error | unchanged (the `codesign` branch stayed as it was) |
| `capture/src/lib.rs` | descriptor directory via `readlink /proc/self/fd/N`; `close_range(CLOEXEC)` with a fallback loop; private base for the profile/state root (§4); processes via `/proc` and `kill(2)` instead of `ps`/`kill`; Chromium note in the session | unchanged (`F_GETPATH`, `ps`) |
| `capture/src/transport.rs` | `pipe2(O_CLOEXEC)` on Linux: closes the window between `pipe()` and `fcntl` | unchanged (`pipe` + `F_DUPFD_CLOEXEC`) |
| `capture/src/browser.rs` (tests) | `lsof`/`ps` via a path that exists (`/usr/sbin` on macOS, `/usr/bin` on Linux) | tests only |
| `recon/` | none | — |

`cfg(target_os)` only where the system differs. `O_NOFOLLOW`, `O_DIRECTORY`, `openat`,
`renameat`, `unlinkat`, `fstatat` and `fdopendir` in `fdio.rs` are POSIX and worked without
changes (verified by the `fdio` tests and by the live tests on Linux). The CDP pipe stays
on fds 3 and 4 (`dup2` in `pre_exec`).

## 3. Browser validation on Linux (equivalent to `codesign`)

On macOS, Chrome is validated by `codesign --verify --deep -R=<Google requirement>`. Linux
has no code signature on the binary (the `.deb` package is signed by the repository key
at install time, but that is not kept in the file). The equivalent, defined and
implemented in `chrome::validate_chrome_linux`, **runs nothing until the end of the
checks**:

1. The given path and the canonical one have no control character and are not non-UTF-8.
2. The path is resolved to the **canonical** one (the links `/usr/bin/google-chrome-stable` →
   `/etc/alternatives/google-chrome` → `/opt/google/chrome/google-chrome` end up at the target).
   If the target is a **script** (`#!`), it is valid only if the **name** is that of a known wrapper of the
   package: `google-chrome` or `google-chrome-stable` (the ELF `chrome` next to it, in
   `/opt/google/chrome/`), `chromium` or `chromium-browser` (the Debian/Ubuntu paths,
   `/usr/lib/chromium/chromium` and `/usr/lib/chromium-browser/chromium-browser`). A script with an
   arbitrary name is refused, never swapped for a binary from somewhere else. What runs is
   always an **ELF**.
3. The executable name is that of a browser (`chrome`, `chromium`, `chromium-browser`).
4. The binary is a **regular file, owned by root (uid 0), executable, not writable by group or
   others**; **every directory above it, up to `/`, is owned by root and not writable by group/others**.
   When the current user is not root, `access(W_OK)` must **fail** for the binary and for
   each directory (covers ACLs and permissions that the mode does not show).
   The file type is checked on the **open descriptor** with
   `O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC` + `fstat`: FIFO, socket and device are
   refused immediately, without blocking (a FIFO with no writer would hang a plain `open` before
   any timeout).
5. **Only then** it runs `<binary> --version` (clean environment, `PATH=/usr/bin:/bin`, 10 s). The
   output must be `Google Chrome <n.n.n.n>` (the stable one: Beta, Dev and "for Testing" have more
   words and are refused) or `Chromium <n.n.n.n> …`. The product and the version come from there.
6. The **owning package** (`dpkg -S`, then `rpm -qf`) is queried and recorded in
   `ValidatedChrome.package`; the validation **does not depend** on it (the system may have neither
   `dpkg` nor `rpm`).

Candidates, in order: `/opt/google/chrome/chrome`, `/usr/bin/google-chrome-stable`,
`/usr/bin/google-chrome`, `/opt/google/chrome/google-chrome`, then Chromium
(`/usr/lib/chromium/chromium`, `/usr/lib/chromium-browser/chromium-browser`,
`/usr/bin/chromium`, `/usr/bin/chromium-browser`). Stable Chrome comes first; Chromium is an
alternative and comes **marked** (`BrowserKind::Chromium`). When the browser is Chromium, the session
records in `capture.notes`: "browser: Chromium (alternative to stable Google Chrome, which does not
exist for this system/architecture)".

**Left out, and stated:** Chromium installed via **snap** — in the round 14 acceptance the
snap Chromium (arm64, 156.0.8078.47) passed the real App battery, with 0 failures
(`tests/results/linux/README.md`). The ELF binary inside the snap is owned by root and meets the rules
above; the **launcher** `/snap/bin/chromium` (what Ubuntu's `apt install chromium-browser`
creates) is neither a candidate nor accepted, because it is a snapd launcher, not the package binary. An
install in a user folder (`~/chrome`, a hand-downloaded binary) is refused on purpose: the
directory belongs to the user.

**Remaining window:** between the check and the `exec` there is a window (TOCTOU), as on macOS. Here
the binary and all directories are owned by root and not writable by the user, so only
root can exploit it, and root can already do everything.

Tests (Linux): `parses_the_version_line_of_each_product_and_refuses_the_others`,
`candidates_list_chrome_before_chromium_and_the_real_binary_before_the_script`,
`a_regular_trusted_elf_passes_every_check_and_only_then_runs_version`,
`a_binary_writable_by_group_or_others_is_refused_before_anything_runs`,
`a_writable_directory_above_the_binary_is_refused`,
`a_file_owned_by_someone_else_is_refused`,
`scripts_and_non_browser_names_are_refused_without_running` (includes a script with an
arbitrary name next to an ELF `chrome`, which is **not** swapped),
`a_fifo_is_refused_immediately_without_blocking` (a FIFO with no writer is refused in under
5 s, proving that the `open` does not block),
`a_symlink_is_resolved_to_the_canonical_binary`, `control_characters_in_the_path_are_refused`
and `the_installed_browser_passes_when_present` (the container's real browser, with version,
kind and package; on arm64 it requires `Chromium`).

## 4. Private directories: profile, NetLog and state root

Everything is still created 0700 and checked after being opened (`create_private_dir_new`,
`verify_private_dir`). What changes is **where**:

- **macOS:** `temp_dir()` (`$TMPDIR` is per user).
- **Linux:** `$TMPDIR`, if the user set it (non-empty); otherwise `$XDG_RUNTIME_DIR`, if it is a
  **real** directory (not a link), absolute, **owned by the current user and with mode 0700**; otherwise `/tmp`.
- The **state root** (orphan markers, rescues) lives in that base. Under a valid `XDG_RUNTIME_DIR`
  it is called `scrapelens-capture-state`; in the shared `/tmp` base the name carries the uid
  (`scrapelens-capture-state-<uid>`), so two users do not contend for the same folder.
- `ensure_private_state_root` creates/tightens the root and checks that it is a directory **owned by the user, 0700 and
  not a link**, **before** any `chmod` (a link in its place is refused without touching the target).
- `is_app_profile` (orphan cleanup) now compares against that base, not against `temp_dir()`.

Tests: `linux_base_dir_prefers_tmpdir_then_a_valid_xdg_runtime_dir_then_tmp`,
`the_state_root_is_created_0700_and_a_symlink_in_its_place_is_refused_untouched`; and the `xdg`
stage of the container (a 0700 `XDG_RUNTIME_DIR`, no `TMPDIR`) shows the profile
`scrapelens-chrome-<pid>-<ns>` and `scrapelens-capture-state` (0700) created **inside it**
during the capture.

## 5. Descriptors, processes and pipes

- **CLOEXEC in the child:** Linux uses `close_range(first, ~0, CLOSE_RANGE_CLOEXEC)` (kernel 5.11+),
  which marks **all** descriptors `>= first` with no scan ceiling; if the syscall does not exist
  (old kernel, seccomp), it falls back to the same loop as macOS (`min(getdtablesize(), 65536)`). With the
  pipe, `first = 5` (3 and 4 belong to the CDP).
- **Pipe:** `pipe2(O_CLOEXEC)` on Linux; on macOS (`pipe` + `F_DUPFD_CLOEXEC`) the minimal window
  remains and is documented in `docs/16b`.
- **Descriptor path** (message when the session folder is swapped): `readlink
  /proc/self/fd/N` on Linux (`F_GETPATH` on macOS).
- **Orphans:** `/proc/<pid>/cmdline` and `kill(2)` in place of `ps`/`kill`, which a minimal
  container may not have.

## 6. Test containers (`experiments/linux/`)

- `Dockerfile`: parameterized by base (`ubuntu:22.04`, `ubuntu:24.04`, `debian:12`) and browser
  (`chrome`: the official `.deb` from `dl.google.com`, amd64; `chromium`: Debian's `chromium`
  package, for arm64), plus Xvfb, Rust (rustup), `cmake`/`clang` (the `testserver`, via quiche, only
  builds with them) and a regular user (`tester`, uid 1001). Chrome runs as that user
  **with the sandbox on** (`--security-opt seccomp=unconfined`, so Chrome can create user
  namespaces); **never** `--no-sandbox` (D6).
- `run.sh <label> <platform> <base> <chrome|chromium> [command]`: builds the image, mounts a
  **read-only snapshot** of the repository and runs `inside.sh`.
- `inside.sh [stages]`: `info`, `clippy`, `unit` (`cargo test --lib`), `live` (the live tests on
  loopback, `--ignored`, under `xvfb-run`, one thread), `recon` (`cargo test` and `live_e2e.sh`),
  `multi` (the `check_multi_target.py`), `xdg` and `mcp`.
- `shim/`: a stand-in for `src-tauri` **in the container only**. `check_multi_target.py` drives
  `cargo test live_bodies_cycle` inside `src-tauri`; without Tauri on Linux, the container swaps
  `src-tauri` for a minimal crate whose test does exactly the same (`scrapelens_capture::run`,
  headless, loopback only). The acceptance script, owned by Tests, was not touched.

## 7. What ran and what did not

**Ran** (all platforms in the table, except where the cell says `—`): `cargo clippy
--all-targets -D warnings` in `capture/` and `recon/`; `cargo test --lib` of `capture/`; the live
tests of `capture/` (`--ignored`, one thread, `xvfb-run`); `cargo test` and `scripts/live_e2e.sh` of
`recon/`; `check_multi_target.py` (16/16 NetLog, ≥15/16 CDP, target types, bodies, no merge,
service worker) with the `testserver` and `scrapelens-core` built in the container itself; the tests
of `mcp/`; the capture with profile and state root under `XDG_RUNTIME_DIR`; the two
`navigator.webdriver` captures with a window under Xvfb (Ubuntu 24.04 amd64 and Debian 12 arm64).

**Did not run, and why:**

- **`src-tauri/` (the Tauri App) on Linux, in this container battery:** it was neither built nor
  tested here; it requires webkit2gtk/GTK and the Linux packaging, which were left to the App stage. The
  `check_multi_target.py` ran with the `shim/` in place of `src-tauri/` (§6), and the 8
  `--ignored` tests of `src-tauri` did not run in the container. In the **round 14 acceptance** the App was
  packaged and validated on the OrbStack VMs (§7.1).
- **RPM distributions** (Fedora, RHEL): not tested. The `rpm -qf` path is coded, but
  was never executed; `dpkg -S` was exercised (Ubuntu and Debian).
- **Other system browsers:** Chrome Beta/Dev/for Testing (refused on purpose). Chromium via snap
  passed the App acceptance (§7.1); the `/snap/bin/chromium` launcher remains outside
  the candidates.
- **`close_range` fallback path** (kernel < 5.11 or seccomp that blocks the syscall): the
  `fcntl` loop is the same code as macOS and passes there, but was not forced on Linux.
- **Read-only mount / ACL** in the browser validation (the `access(W_OK)` for a non-root
  user): covered by the code, not by a test (the mode and owner tests cover the rest).
- **x86 emulation:** the amd64 runs go through emulation (OrbStack), so the live-test times (≈ 280 s)
  do not count as performance; native arm64 takes ≈ 200 s.
- **HTTP/3, other CPUs, Wayland:** outside what the capture tests on loopback.

### 7.1 App acceptance on the OrbStack VMs (round 14)

Run of the real packaged App, recorded by Tests/App in `tests/results/linux/README.md`
(artifacts `src-tauri/linux/out/` of commit `23bb4ec`): two Ubuntu 24.04 VMs, amd64 on
Rosetta with Google Chrome 156.0.8078.79 from the official repository, and native arm64 with **Chromium
156.0.8078.47 from the snap**. With the `.deb` installed (`ScrapeLens_0.1.0_amd64.deb` and
`ScrapeLens_0.1.0_arm64.deb`; also the `AppImage` of both architectures), **0 failures** on each
machine: start and quit by shortcut, `complete` capture with 11 requests, HAR `complete` 24,
NetLog `partial` 32, `navigator.webdriver === false`, no LISTEN socket from the capture's Chrome.

It is the proof that this module's browser validation works with the repository's Chrome and with
the snap's Chromium in the real App; the container battery in the §1 table remains the proof of
`capture`/`recon` per platform.

**macOS regression:** none. The list in the table is the same as before (clippy, 91 unit, 17 live,
recon, `src-tauri` 56 passed, mcp, `check_multi_target` OK); the `cfg(target_os = "macos")` branches
(`codesign`, `plutil`, `F_GETPATH`, `ps`, `pipe` + `F_DUPFD_CLOEXEC`) were not touched.

**How to repeat:**

```
experiments/linux/run.sh u24-amd64 linux/amd64 ubuntu:24.04 chrome       # stable Chrome
experiments/linux/run.sh d12-arm64 linux/arm64 debian:12 chromium         # Chromium (arm64)
# stages: info clippy unit live recon multi xdg headed mcp (default: info clippy unit live recon)
experiments/linux/run.sh u24-amd64 linux/amd64 ubuntu:24.04 chrome /src/experiments/linux/inside.sh multi xdg
```
