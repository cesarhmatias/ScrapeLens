# Review of the ports from origin/main (before the T21 push)

Independent read-only review, 2026-11-07, of `main` at `7ea51d1` against `origin/main` at
`572f30f` (v0.1.3 line). Question: does `main`, which carries origin's security fixes as
separately written ports, keep every protection? Severity: no high or medium findings.

## Verdict by origin commit

| origin commit | verdict | where on main |
|---|---|---|
| 10b07c8 match the whole 4-tuple | kept | `capture/src/relay.rs:514-528`; `relay_peer.rs:603-624` |
| bc16179 flood cannot take tunnel slots | kept | `relay_peer.rs:63-109, 189-210`; `relay.rs:128, 278` |
| 6de3526 no owner (inode 0) means closed | kept | `relay_peer.rs:436` |
| c7e8799 close relay when the browser exits | kept | `capture/src/lib.rs:583-585`; `relay.rs:360` |
| 92b8fd3 one owner-tree check per generation | weakened (finding 5) | `relay_peer.rs:227-260, 308-371` |
| 80ef2fc one 3 s window | kept | `relay_peer.rs:52, 323-326` |
| d25ef55 a miss is final after one generation | kept | `relay_peer.rs:59` |
| 9bbf214 evict the oldest waiter, size from RLIMIT_NOFILE | kept | `relay_peer.rs:141-175`; `relay.rs:128-145, 634` |
| 6507bfa libproc counts and errors | kept | macOS module identical to origin |
| 9505ae2 tests | kept | `relay.rs:2813, 2848` |
| 52937ed search rights on ancestors | kept | `core/src/store.rs:135-139, 302-344` |
| 49237d0 O_NONBLOCK, refuse non-files | kept | `store.rs:766-777, 873-884` |
| 31cb2b2 cleanup through the directory descriptor | kept | `store.rs:735-738, 896-919`; `mcp/src/tools.rs:931-948` |
| b247601 validation run through descriptors | weakened (findings 1, 2); open-files limit kept | `src-tauri/src/validation.rs:99-111`; `store.rs:743-757` |
| 69e58ad text export and cleanup through descriptors | kept | `src-tauri/src/export.rs:288-306, 509-526` |
| d68860f `..` from the descriptor, system links only | kept | `src-tauri/src/fsfd.rs:51-101` |
| e804fb3 MCP open-files limit | kept | `mcp/src/harden.rs:23-46` |

No relay or file-safety test was lost by name.

## Third review (`sl-review-013`, section "Third review")

M-A, L-3, L-6, L-7, the flaky test and the ENOTDIR note are closed. L-2 and L-5 are closed with
a residual (finding 4). L-4 is still open in the Tauri and MCP export cleanup (finding 3). The
M-A memory bound on main was not re-measured, and L-6 has no test.

## Findings (all low)

1. `keep` reads the run through a swapped ancestor link. `copy_tree_from` opens the full path
   and refuses a link only at the last component (`store.rs:747`). With an ancestor swapped by
   a same-user process, main returned Ok after copying the attacker's tree in 5 of 7 runs of
   400 calls; origin in 0 of 6.
2. `keep` copies into a folder it did not create: main drops the descriptor from creating the
   new folder and re-walks `parent/name` (`validation.rs:99-111`). A renamed same-user folder
   received the run in 3 of 7 runs; origin 0 of 6.
3. L-4 still open: cleanup after a failed export re-opens the parent by path
   (`export.rs:518-526`, `tools.rs:940-948`). A swapped parent made the cleanup delete a planted
   folder's same-named entry every time, on macOS and Linux. Same code on origin; not a
   regression.
4. L-2 and L-5 residual: the immediate parent is opened `O_RDONLY` (`fsfd.rs:75`,
   `store.rs:312`). Under a 0311 parent, `keep` and `write_text_file` fail with EACCES and both
   cleanups leave the partial export. Tauri cleanup also skips a destination whose name contains
   `\` (`validate_attachment_name`).
5. Torn-read guard removed (92b8fd3): origin's `client_once` refused two rows on one connection
   with different inodes or uids; main returns the first match (`relay_peer.rs:603-624`). Not
   shown to be exploitable.
6. The flaky-test fix weakens its test: the loop retries until it sees `ALREADY_CLOSED`, so an
   `Ok(())` on an earlier attempt (a stranger admitted) is ignored (`relay.rs:2786-2807`).
7. Info: `write_private_bytes` and `refuse_foreign_owner` are test-only now
   (`tools.rs:751, 799`); their tests cover code production no longer calls.

## Corrections to `merge-origin-main.md`

- Row 17: "copy_tree_at/remove_path not needed (core covers)" is false; see findings 1 and 2.
- Row 11: the O_NONBLOCK that 49237d0 needs is at `store.rs:766` and `:873`, not `:694`.
- Row 6: the line is `relay_peer.rs:436`.
- The M-A port removed the torn-read guard (finding 5).

## How it was verified

By reading: `git show` of each commit, whole-file diffs, a check of each commit's added lines
against both trees, test names compared across trees. By running: macOS relay, core store, MCP
and app suites; proof tests for findings 1 to 4 and 7 against main and origin; Linux arm64
(Docker, uid 1000) relay 40/40, the flaky test 300 times, core, MCP and the export harness.

Not verified: the M-A memory bound on main, L-6 by running, whether finding 5 is exploitable,
the app crate on Linux, Linux amd64, real Chrome, running as root.
