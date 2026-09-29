<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# GA track step 1 — CLI and command-surface audit

Status: EXPERIMENTAL
Implements: SCOPE-070, SCOPE-071, SCOPE-072, SCOPE-077

The GA track's first step (roadmap, owner directive 2026-09-27). Measured on `main` after
Lane B, unprivileged, with a development state root; no privileged or full collection was
run. Each finding is classified by the GA question: does it stop GA?

## What the command surface is today

| Command | Does | Exit |
|---|---|---|
| `isedraf identity` | collects host identity, commits a snapshot, appends the ledger, verifies the store | 0 / 2 / 64 / 70 |
| `isedraf inventory [--json] [--root]` | collects and prints the nine inventory subdomains; commits nothing | 0 / 2 / 64 |
| `isedraf report [--json] [--save] [--profile]` | JSON or Markdown from the committed identity plus a fresh inventory collection | 0 / 2 / 64 / 70 |

Every run needs `ISEDRAF_STATE_ROOT` and is marked `DEV`; root and sudo are refused.

## Findings

| # | Finding | Stops GA? | Disposition |
|---|---|---|---|
| CLI-1 | a usage error (unknown command or option) exited 2, the frozen code for incomplete evidence (SCOPE-077 maps usage to 64) | YES | fixed: usage errors exit 64; test and injection `GA-CLI-1` |
| CLI-2 | nine built collectors - accounts, NSS topology, hostname, sudo, SSH, PAM, authorized_keys, login policy, mounts - are reachable from no command, and there is no `audit` command | YES | GA step 1 work: one `audit` command (below) |
| CLI-3 | ISEDRAF had no production mode: root and sudo are refused, there was no default state root, and every artifact was `DEV` | YES, at product level | **resolved by owner decisions D-116 and D-117**: GA v0.1 is unprivileged; the user-mode production store (`USER_PRODUCTION`, STORE-026) is built, fails closed on unsuitable storage (STORE-027), and every run states PRIVILEGE LEVEL: UNPRIVILEGED. Privileged Full Audit stays deferred (SCOPE-072) |
| CLI-4 | `report` collects a fresh inventory and combines it with committed identity, so a report is not built only from committed evidence | YES for the first report | addressed by `audit`: collect, commit, then render from what was committed |
| CLI-5 | lock contention and an unwritable state root exit 64, while the full product defines 66 and 67 | NO | correct under the frozen W1-A exit set (SCOPE-077); 66 and 67 arrive with the full contract |

## The `audit` command (proposal for CLI-2 and CLI-4)

One command that runs every built collector once, with the NSS context passed explicitly
(IQ-036, IQ-037), commits the result, and renders the first report from the committed
evidence only. The frozen W1-A snapshot covers host identity; the other domains follow the
precedent inventory already uses: an evidence artifact bound to the identity snapshot by
digest, outside the frozen snapshot contract (SNAP-021).

## Implementation status

`isedraf audit` is built on `ga/audit-command`: each of the ten sections is collected once
(NSS context passed explicitly), written as `sections/<name>.json` inside the snapshot
bundle, bound by D-115's `auxiliary_artifacts` outside `state_hash`, and committed by the
existing atomic rename and ledger append - no second commit mechanism. `isedraf report`
renders only the latest ledgered run and refuses when it has no audit sections.

While wiring it, the report was found to select the newest snapshot DIRECTORY rather than
the last LEDGER record, so an orphan (renamed, never ledgered) would have been reported
as the run. It now follows the ledger (GA priority 4; regression test first).

**Merge blocked on the owner's GA v0.1 amendment:** the D-115 authoritative set is a
contract, and `test_auxiliary_binding` pins it exactly; the ten section paths join it by
owner decision of 2026-09-27 whose amendment text is pending. Production commits into the
USER_PRODUCTION store come with the same amendment.

## After D-116 and D-117

- The audit branch merged once D-115 was extended with the ten section paths.
- `USER_PRODUCTION` is the default when no `ISEDRAF_STATE_ROOT` is set. Its root must be the
  invoking user's directory with mode 0700; storage is checked before anything is created
  or collected, and NFS, CIFS/SMB, FUSE and any filesystem not known to be suitable are
  refused. The verifier accepts only the three `state_root` literals.
- **Registered, not GA blockers:** a storage refusal exits 64, because the frozen W1-A exit
  set has no 67 (state root unwritable) - that code arrives with the full exit contract; and
  a store deliberately placed on tmpfs is accepted (its commit semantics hold) but does not
  survive a reboot.
