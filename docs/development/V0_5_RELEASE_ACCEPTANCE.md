<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# v0.5 release acceptance record

Status: IMPLEMENTED, released in 0.5.0 (2026-11-21). A historical record of how v0.5 was built and accepted.

Implements: D-129

What is verified for v0.5, on which tree, and what remains before the release candidate is accepted.
The register (`docs/development/V0_5_OPERATOR_EXPERIENCE.md`) holds the items and their status; this
page holds the evidence. Owner rule (2026-11-16): targeted falsification during development, the
hooks (`make check`) on every commit, and one full falsification run on the release candidate. A
full run that passed on an earlier tree and targeted checks after later edits are recorded as such,
never merged into one claim.

## 1. Batches (engineering branch `design/v0.5-operator-experience`)

| Batch | Commit | Checks on the build VM | Installed-package check (lab) |
|---|---|---|---|
| B1 command table, help | `8eab0cd` | `make check` | with B2 |
| B2 bash completion, packaging | `e35be2d`, `eb231a0` | `make check`; injections | Ubuntu 24.04, Debian 12, AlmaLinux 9.7, 8.10 (`b2-completion-20261113`; development build labelled 0.4.0) |
| dev versions | `5bb081f` | `make check`; ordering with dpkg and rpm | - |
| B3/B4 start page, root help (`D-129` point 10) | `d9d0472`, `52fd4bb` | full falsification passed on the kit tree | Ubuntu 24.04, Debian 12, AlmaLinux 9.7; AlmaLinux 8.10 limitation (`b34-help-20261114`) |
| B5 header, audit summary | `a9daa5e` | `make check`; injections; a later full run found one stale anchor, fixed in `1ea391a` | real output on the build VM |
| B9 free space, exit 68 (`D-129` point 11) | `1ea391a` | full falsification passed on the kit tree | Ubuntu 24.04, AlmaLinux 9.7 (`s1-space-20261115`) |
| CI time limit | `8ce07f4` | `make check` | - |
| B7 `isedraf list` (`D-129` point 11) | `3619ae7` | full falsification 588/588 on the kit tree | Ubuntu 24.04, AlmaLinux 9.7 (`b7-list-20261115`) |
| B6 Full Audit summary, approval display | `1d6d5d6`, `85f4e23` | full falsification 590/590 on each tree | Ubuntu 24.04 Full Audit (`b6-fullaudit-20261116`) |
| B8 `sudo isedraf list`, refusals (`D-129` point 12) | `8efab22` | full falsification 594/594 on an earlier B8 tree; after the final layout edits, the 9 injections touching `summary.py` and the listing | Ubuntu 24.04 Full Audit, AlmaLinux 8.10 (`b8-refusals-list-20261116`) |
| B10 report order, documentation check, install text | `88b2907` | `make check`; the 22 injections touching the report renderer and the command gate | - |
| STORE-016 ledger recovery (owner kit, `D-129` point 13) | `3f026db`; operation list and user report/list refusal `36c29b8` | `make check`; the 6 new recovery injections and the 32 existing ones touching the ledger and the Full Audit routes | Full Audit recovery on a lab host (in this kit) |

| Release candidate 0.5.0-rc1 | `f22631d` | full falsification 601/601 | section 2 |
| Release candidate 0.5.0-rc2 | `6499b44` | full falsification 601/601 | section 3 |
| Release candidate 0.5.0-rc3 | `46349ad` | full falsification 601/601 | section 4 |
| Terminal UX, every command (owner GO 2026-11-20) | `16fec88`, `0a9776c`, `89a2e3a` | `make check` with `tests/test_terminal_width.py`; lab sweep 109/109 | section 5 |
| Release candidate 0.5.0-rc4 | `d8da2c7` | full falsification 601/601 | section 5 |
| Release 0.5.0 (owner GO 2026-11-20) | `8da0220` (`release/v0.5`); published 2026-11-21 as tag `v0.5.0` | `make check`; full falsification 601/601; upgrade from the published 0.4.0 package (Rocky 9.7) and the 109-case sweep (Debian 12, AlmaLinux 9.7); on the public tree, falsification 592 + 11 declared skips; the tag-built packages attested and smoke-tested (Debian 12, Rocky 9.7) | section 5 |

## 2. Release candidate 0.5.0-rc1 (`f22631d`, 2026-11-17)

- **Full falsification** on this tree: 601 executed and detected, 0 unexpected non-firing.
- **Installed packages** built from `f22631d` (deb `cdd9c415…`, rpm `88f30116…`), on five lab
  hosts (evidence `acc-rc1-20261117`):
  - **Upgrade from the published 0.4.0** on three platforms: Rocky Linux 9.7 (already on 0.4.0),
    Debian 12 and AlmaLinux 8.10 (first reinstalled to the published 0.4.0 package and audited with
    it). Ubuntu 24.04 and AlmaLinux 9.7 started from development builds, not from 0.4.0. On every
    host the upgrade left the personal and system stores unchanged (same content hash).
  - Help, the start page, completion and the offline command reference, from the package.
  - User route, torn ledger in a development store: `isedraf report`, `isedraf list` and `isedraf
    evaluate` exit 64 and the store is unchanged; `isedraf audit` recovers; afterwards `list`,
    `report` and `evaluate` read both segments.
  - Full Audit route (Ubuntu 24.04, Debian 12, AlmaLinux 9.7, Rocky Linux 9.7), on a fresh store
    while the real one was moved aside and later restored unchanged: the same refusals (64, store
    unchanged), recovery by `sudo isedraf audit`, both segments read by `sudo isedraf list`,
    `report` and `evaluate`, and `sudo isedraf baseline approve` showing the approval before writing
    (exit 0).
- **Free space, two separate proofs:**
  - The Full Audit refusal before anything is written: a 4 MiB system store, `sudo isedraf audit`
    exits 68 and the store holds no file - **lab-tested on four hosts** (with the user route on
    Ubuntu 24.04 and AlmaLinux 9.7 in `s1-space-20261115`).
  - Space running out during a commit or a recovery, after the preflight passed: **unit-tested only**
    (`tests/test_space.py`, `tests/test_ledger_recovery.py`); accepted for v0.5 by the owner
    (2026-11-20). On a real host it needs a concurrent writer at the same moment.
- **Finding:** four messages were longer than 80 columns (the ledger-recovery notice, the user and
  Full Audit evaluate refusals, the Full Audit free-space refusal). Owner: fix in an internal rc2.

## 3. Release candidate 0.5.0-rc2 (`6499b44`, internal, 2026-11-20)

- `make check` passed in the commit hook; **full falsification** on this tree: 601 executed and
  detected, 0 unexpected non-firing.
- Installed packages built from `6499b44` (deb `2c0c1693…`, rpm `4e4a1a70…`) on Ubuntu 24.04 and
  AlmaLinux 9.7, each command in a pseudo-terminal set to 80 columns (evidence `acc-rc2-20261120`):
  the four rc1 findings fit 80 columns with their exit codes unchanged - the user and Full Audit
  evaluate refusals (64, store unchanged), the Full Audit free-space refusal (68, no file written)
  and the recovery notice on both routes (the audit then continues, 2). Real stores restored
  unchanged. The `^@` before some sudo lines is the terminal echo of sudo, not ISEDRAF output.
- **New finding:** the 80-column terminal showed three more lines over 80 columns in the audit
  summary's standard output (the host-identity line with its hash, the development-store note, the
  privilege line). The rc1 measurement had covered standard error only. Owner: fixed in rc3.

## 4. Release candidate 0.5.0-rc3 (`46349ad`, internal, 2026-11-20)

- The three audit-summary lines wrapped (the host id, a hash, on its own line, never split). The
  README shows the logo (`docs/assets/LOGO.md`). **Full falsification** on this tree: 601 executed
  and detected, 0 unexpected non-firing.
- Installed packages from `46349ad` (deb `6b6d9c73…`, rpm `5dfe206a…`) on Ubuntu 24.04, Debian 12
  and AlmaLinux 9.7, 80-column pseudo-terminal (evidence `acc-rc3-20261120`): the start page, the
  audit on both routes, `sudo isedraf list` and the four rc1 cases fit 80 columns with the
  expected exit codes; real stores restored unchanged.
- **Finding:** a sweep of every user-route command found more lines over 80 columns (`explain`,
  `help --all`, `list`, `identity`, three refusals). rc2 and rc3 had each checked only the outputs
  of the previous finding. Owner GO 2026-11-20: finish the terminal UX of every command in v0.5,
  with a permanent coverage check, as rc4.

## 5. Release candidate 0.5.0-rc4 (internal)

The rule (owner, 2026-11-20): human terminal text fits 80 columns on every implemented command,
on both routes. An identifier, path, digest, JSON pointer or code span is never split; it may
pass 80 columns only alone on its line (`summary.within_terminal`), and each such case is named
below. The Markdown, HTML and JSON reports follow their own formats; the messages around them
are held to the rule.

- **Fixed:** `explain` (every criterion: prose wraps, each evidence pointer on lines of its own),
  `help --all`, the listing (evaluation and snapshot IDs on separate lines; long store and report
  paths alone), the identity, inventory and evaluate views (a long value under its label), the
  argument errors (no usage block; the commands and where to look), and the refusals for an
  unknown criterion, no committed run, an unusable system store and `sudo isedraf list` with no
  store; the baseline approval's next step.
- **Permanent check:** `tests/test_terminal_width.py` - a coverage table of commands and cases
  (every help form, every command's `--help` and `help COMMAND`, every criterion, an empty store,
  committed runs, saved reports, a torn ledger, wrong arguments, refusals) on the user route under a
  deliberately long store path, and the root route's launchers; a command of the command table
  without a case fails it. In the lab, `kits/sweep/sweep.sh` runs 109 cases on both routes from the
  installed package in an 80-column pseudo-terminal, with exit codes and store checks.
- **Named exception:** the path of a saved report (`.../reports/YYYY/MM/RPT-...md` or `.html`),
  printed alone on its line after `report --save` and in `isedraf list`. Under a home directory it
  can pass 80 columns; it is never split, so it can be copied whole.
- **Pre-rc4 lab sweep** (packages from `89a2e3a`, Ubuntu 24.04): 109 of 109 cases as expected.
- **rc4 `d8da2c7`:** `make check` passed in the commit hook; **full falsification** on this tree:
  601 executed and detected, 0 unexpected non-firing.
- **Installed rc4 packages** (deb `a1c10457…`, rpm `4fc0769e…`, source commit recorded and checked
  before each run) on Ubuntu 24.04, Debian 12 and AlmaLinux 9.7, the sweep in an 80-column
  pseudo-terminal (evidence `acc-rc4-20261120`): **109 of 109 cases as expected on each host** -
  exit codes (0, 2, 64, 65, 67, 68, 70 where each applies), no line over 80 columns except the named
  exception (6 saved-report paths per host, each alone on its line), the 6 refusals on a torn
  ledger leaving the store unchanged, the 4 MiB store refused with no file written, recovery on
  both routes continuing into a new segment, the user-store approval refused (65) with the store
  unchanged. Real system stores restored unchanged; test stores kept.

## 6. Not in v0.5, stated

R2's choice of another visible destination for a saved report; P6 (baseline preview, design only);
another interpreter for the root route on hosts without `/usr/bin/python3` (IQ-078, decided A);
`STORE-021` (segment number and head recorded outside the ledger): no protection against the deletion
of whole segments is claimed.
