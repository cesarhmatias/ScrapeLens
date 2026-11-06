# Browsers on Linux: what the App accepts

The App checks the browser it starts (`src-tauri/src/browser_check.rs`). The check reads the
file and its directories; it never runs the file.

## Accepted

- **ELF binaries** named `chrome`, `chromium`, `chromium-browser`, `brave`, `brave-browser`,
  `msedge` or `microsoft-edge`, wherever they live (portable builds included).
- **Launcher scripts** named `google-chrome`, `google-chrome-stable`, `google-chrome-beta`,
  `google-chrome-unstable`, `chromium`, `chromium-browser`, `chromium-browser.sh`,
  `brave-browser`, `brave-browser-stable`, `brave`, `msedge`, `microsoft-edge` and
  `microsoft-edge-stable`, only when the resolved path (symlinks followed) is in a system
  directory: `/usr/bin`, `/usr/local/bin`, `/usr/lib/chromium`, `/usr/lib/chromium-browser`,
  `/usr/lib64/chromium`, `/usr/lib64/chromium-browser`, `/opt/google/chrome`,
  `/opt/google/chrome-beta`, `/opt/google/chrome-unstable`, `/opt/brave.com/brave`,
  `/opt/microsoft/msedge`. The file and every directory above it, up to `/`, must be owned by
  root and not writable by group or others.

## Refused

- Shells, arbitrary files, directories, FIFOs and devices.
- Launchers in a user folder, even with a browser name, and launchers that are group-writable,
  other-writable or owned by another user.
- **Snap and Flatpak wrappers** (`/snap/...`, `/var/lib/flatpak/...`, or a path that resolves to
  `snap` or `flatpak`). The App does not yet know how to start them. Choose a browser installed
  from a `.deb` or `.rpm` package, or its real executable.

## Checked

Containers (arm64), each run as root with the distribution's own package where one exists:

| Distribution | Browser | `detect` result | App |
|---|---|---|---|
| Debian 12 | `chromium` | `/usr/lib/chromium/chromium` (ELF) | accepted |
| Ubuntu 22.04 | `chromium-browser` | `/usr/bin/chromium-browser` (root-owned script) | accepted |
| Ubuntu 24.04 | `chromium-browser` | `/usr/bin/chromium-browser` (root-owned script) | accepted |
| Fedora 41 | `chromium` | `/usr/bin/chromium-browser` → `chromium-browser.sh` | accepted |

The launcher permission cases were run with simulated launcher files: Chrome itself was not
installed in the containers.

## Known limits

- **Ubuntu `chromium-browser` starts a snap.** The App accepts the launcher, but starting it was
  not tested. It needs snapd on the machine.
- **Chrome Beta, Dev and Canary on macOS and `com.google.chrome.for.testing`** bundle identifiers are
  not checked against an installed app. A wrong identifier only refuses that browser, with a message.
- **`/opt/brave.com/brave`** is the expected Brave directory and was not checked on a machine with Brave.
- **amd64** was not run; the containers were arm64.
- **Controlled capture** uses a stricter validator (`capture/`, `validate_chrome`) that accepts only
  stable Chrome. The App's list is wider than the capture's by design.
