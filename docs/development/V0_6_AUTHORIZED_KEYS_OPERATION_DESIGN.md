<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# v0.6 — a fifth fixed operation for authorized_keys: owner design

Status: PLANNED - not in 0.6.0. The design needs a revision (the allowed-path rule for a prefix taken from host configuration) before any implementation.

Implements: D-129, D-123, D-124

Owner direction 2026-11-21: design a fifth fixed operation now; before it is implemented, the owner
kit must state which paths are allowed, how symbolic links and files changing during the read are
handled, the size bounds, and what reaches the evidence. The operation widens **data access**, even
with the same capabilities. If the design does not close safely, authorized_keys stays `NOT_TESTED`,
as documented today. Nothing here is implemented.

## 1. Facts

| # | Fact | Label |
|---|---|---|
| A1 | The Full Audit reads with privilege only through four fixed operations, each with **constant targets** compiled into the package (`supervisor/contracts.py`, `AUTH-017` to `AUTH-031`) | REPOSITORY FACT |
| A2 | On a 0.5.0 Full Audit (Ubuntu 24.04) all 37 accounts are `UNRESOLVED_SOURCE_UNIVERSE`: 84 candidate files `PERMISSION_DENIED` (`/root/.ssh`, `/home/*/.ssh`, `/etc/ssh/keys`, mode 0700), 64 `NOT_FOUND` | OBSERVATION |
| A3 | Evidence per key line: SHA-256 fingerprint of the decoded blob, key type, option **names** (every option value `NOT_RETAINED`), `comment_present` with a retention policy; no comment text | REPOSITORY FACT (`authorizedkeys/model.py`, `sources.py`) |
| A4 | The two existing `read_fixed_tree` operations open with `O_NOFOLLOW`, accept regular files only, and bound each member (1 MiB) and the whole (4 MiB) | REPOSITORY FACT (`supervisor/perform.py`) |
| A5 | The root supervisor holds no analysis code; the engine, unprivileged, parses | FROZEN REQUIREMENT (`FULL_AUDIT_AUTHORITY_MODEL.md`) |

**The new problem.** Unlike A1, the files to read are named by host data: each account's home
directory and the effective `AuthorizedKeysFile`. A privileged read at a host-derived path is a new
class of operation. Three rules follow, and the rest of the design serves them:

1. **The supervisor derives every target itself**, from sources it reads as root. It never accepts a
   path, a name or a pattern from the engine.
2. **Every path is opened component by component without following a link.** A host-derived path is
   where a link-swap would redirect a privileged read.
3. **Only what the evidence contract already keeps leaves the engine** (A3).

## 2. Allowed paths (decision D1)

- **Accounts:** local `/etc/passwd` entries only, as the supervisor reads them; at most 4096. NSS and
  directory accounts are out of scope (as for the accounts section).
- **Patterns:** the global effective `AuthorizedKeysFile` from `resolve_sshd_effective_config_v1`; at
  most 8 patterns. `Match`-scoped values are not used (the operation has no connection context, as
  `sshd -T` has none).
- **Tokens:** `%h`, `%u`, `%U`, `%%` only. A pattern with any other token, or `AuthorizedKeysCommand`,
  is not read: `NOT_TESTED` with reason `PATTERN_NOT_SUPPORTED`.
- **Expansion:** a relative pattern is joined to the home directory. The result must be absolute,
  normalised, without `..`, `.` or empty components, and under the home directory (relative patterns)
  or under the pattern's own fixed prefix (absolute patterns such as `/etc/ssh/keys/%u`). Anything else
  is `NOT_TESTED`, reason `PATH_OUTSIDE_ALLOWED_ROOT`.
- **Never:** a path containing a control byte, longer than 4096 bytes, or whose home directory is `/`,
  relative, or missing.

## 3. Symbolic links and files that change (decision D2)

- **Walk:** from `/`, each directory component with `openat(O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)`. A
  link at any component stops the walk: `NOT_TESTED`, reason `SYMLINK_NOT_FOLLOWED`, recording that a
  link was there and where, never its target.
- **File:** `openat(O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)`; regular files only (else `NOT_TESTED`,
  `NOT_A_REGULAR_FILE`).
- **Change during the read:** `fstat` before and after; if `st_dev`, `st_ino`, `st_size`,
  `st_mtime_ns` or `st_ctime_ns` differ, the bytes are discarded: `NOT_TESTED`, `CHANGED_DURING_READ`.
  No retry: a retry would turn a race into a silent result.
- **Metadata reported** for the file and each directory: owner uid, group gid, mode - the facts behind
  sshd's `StrictModes`, as observations.

## 4. Bounds (decision D3)

| Bound | Value | When exceeded |
|---|---|---|
| bytes per file | 256 KiB | `NOT_TESTED`, `SIZE_BOUND_EXCEEDED`, bytes discarded |
| files per run | 4096 accounts x 8 patterns, never more than 8192 opened | the remaining files `NOT_TESTED`, `RUN_BOUND_EXCEEDED` |
| bytes per run | 16 MiB | as above |
| time | 30 s | as above, `TIMEOUT` |

The bounds are a proposal; the lab corpus measures them before the kit.

## 5. What crosses, and what reaches the evidence (decision D4)

- **Supervisor to engine:** per target, the path, the metadata of section 3, and the file's bytes, on
  the existing run-private framed pipe. Nothing is written by the supervisor.
- **Engine to evidence:** exactly A3 - fingerprint, key type, option names, `comment_present` - plus
  the metadata and the per-file collection status. The bytes are never committed, never logged and
  never in a diagnostic.
- **Proof required before release:** a test fixture with a distinctive comment, option value and key
  blob proves none of them appears in any committed file.

## 6. What changes, and where the owner decides

| Change | Where | Owner act |
|---|---|---|
| new `AUTH-0nn` for `read_authorized_keys_v1`: data-derived targets, sections 2 to 5 | `FULL_AUDIT_AUTHORITY_MODEL.md` (frozen) | amendment |
| contract and registry entry | `supervisor/contracts.py`, `scripts/ci/privileged_operations.json` | owner kit (`check-privileged-operations` holds them equal) |
| new performer `read_derived_files` | `supervisor/perform.py` | owner kit, with tests |
| collector uses the operation under Full Audit; Standard Audit unchanged | `authorizedkeys/` | owner kit |
| `parser_version` of the authorizedkeys section | `audit.METHODS` | owner kit; the section is outside the baseline profile and `state_hash` |

## 7. Tests the kit carries

Normal (root, user, `/etc/ssh/keys/%u`); missing home and missing file; a link at the file and at a
directory component; a file replaced and a file grown during the read; oversize file; more accounts
than the bound; a pattern with an unsupported token; a pattern escaping the home directory; the
privacy fixture of section 5; and the falsification injections that prove the gate refuses an
operation whose targets come from the engine.

## 8. If it does not close

Any of D1 to D4 refused, or a lab platform where the walk of section 3 cannot be done without a
capability beyond `AUTH-027`: the operation is not built, and authorized_keys stays `NOT_TESTED` under
private directories, documented as today (OD-06 rule: never widen capabilities).
