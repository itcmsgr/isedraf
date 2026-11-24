<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# v0.6 Release acceptance record

Status: IMPLEMENTED, released in 0.6.0 (2026-11-24). A historical record of how v0.6 was built and accepted.

Implements: D-130, D-129

What each v0.6 batch changed, its commit, and how far it is verified. Two levels are kept apart, as
the owner asked: **automated** (`make check`, the falsification harness, unit and end-to-end tests,
package contents inspected on the build VM) and **installed** (the DEB or RPM installed on a lab host
and the behaviour checked there). Design and scope: `V0_6_NATIVE_COVERAGE_DESIGN.md`.

## 1. Batches (engineering branch `design/v0.6-native-coverage`)

| Batch | Commit | Automated | Installed |
|---|---|---|---|
| v0.6 coverage matrix and design | `edaab69`, `624b777`, `3f1b2d3` | `make check` | - (documents) |
| Documentation alignment; stale-prose check (G1) | `d1c83ec` | `make check`; the 8 documentation-gate injections, 2 of them new | - |
| Every `make check` target classified (G2); "codename" leaves the engineering files (D-108) | `e8a93d3` | `make check`; 3 new injections | - |
| Owner kit: the native criteria catalogue (D-130) | `05c021c` (tree `37739c86`) | `make check` through the hooks; the 3 D-130 injections; catalogue, explain and 80-column tests; DEB and RPM contents | section 2 |
| Owner kit: "codename" leaves the owner-controlled files (D-108); W1-A re-freeze of `HEADER_POLICY.md` | `8fb3b39` (tree `93ed95f3`) | `make check` through the re-installed hooks; the governance, freeze, pre-commit and header injections | - (no runtime change) |
| Development builds are 0.6.0-dev | `9146769` | `make check` | section 2 |
| PAM `@include` read where libpam reads it (parser version 2) | `c5bf4e5` | `make check`; 10 new PAM tests; 2 new injections | section 3 |
| Owner kit: the first PRIV criteria and the NO_BASELINE wording (D-131) | `8131136` (tree `463019f2`) | `make check` through the hooks; 4 PRIV injections; every test file; DEB and RPM contents | section 4 |
| Owner kit: four more criteria, SSH and the first STORAGE (D-132) | `92f579e` (tree `7e45895f`) | `make check` through the hooks; 3 new injections; every test file; DEB and RPM contents | section 5 |
| Report: nullok beside ISE-ACCOUNT-002, maximum password age per account (D-132 point 3) | `5692da7` | `make check`; 8 new tests; 2 new injections; the full falsification run on that tree, 620 executed and detected | section 6 |
| Release candidate 0.6.0-rc1 | `bf0c0a6` | the full falsification run on this tree | section 6 |
| Release 0.6.0 (owner GO 2026-11-24; version only, from `bf0c0a6` and its acceptance record `1f43fc3`) | this commit | `make check` | packages of the release build |

## 2. Installed packages: the catalogue (2026-11-23)

Packages built from `9146769` (deb `d10bf08c…`, rpm `596b0bf6…`, source commit checked on each host),
installed over the published 0.5.0 on Debian 12 (DEB) and Rocky Linux 9.7 (RPM), evidence
`v06-catalogue-install-20261123`:

- install succeeded; the package files verify with no deviation; the system evidence store was
  unchanged by the upgrade;
- `/usr/share/doc/isedraf/docs/reference/NATIVE_CRITERIA.csv`: no byte-order mark, 8 rows, 15
  columns, read by a CSV parser; every `documentation` link resolves to its installed page under
  `docs/reference/criteria/`;
- `isedraf explain` for each of the 8 criteria: exit 0, the title, the release that introduced it and
  the minimum collection route; the widest line 79 columns; the baseline lines describe the
  capability ("belongs to an evidence store, not to a criterion") and the stale "baseline and delta
  are v0.4" text is gone; an unknown ID exits 64.

## 3. Installed packages: PAM `@include` (2026-11-23)

Packages built from `c5bf4e5` (deb `cb84f325…`, rpm `9c164fac…`), evidence
`v06-pam-install-20261123`. A Full Audit into a fresh system store (the real one moved aside and
restored unchanged) and a Standard Audit, each read back from the committed PAM section:

| Host | `@include` files | PAM section before (0.5.0) | PAM section now | Records |
|---|---|---|---|---|
| Ubuntu 24.04 (DEB) | 13 | PARTIAL: 35 of 113 lines unread | COLLECTED, Full and Standard Audit | 72 rules, 41 edges (35 `@include`), 0 unsupported; basis Debian family (`ID_LIKE=debian`) |
| Rocky Linux 9.7 (RPM) | 0 | COLLECTED | COLLECTED, Full and Standard Audit | 117 rules, 57 edges, no `@include`; basis not Debian family |

**What the basis is, and is not (INFERENCE).** The collector takes the platform family from
`/etc/os-release` (`ID`, `ID_LIKE`) and treats a Debian-family host as one whose libpam reads
`@include`. That is an assumption about the installed libpam, not a check of it: no library is
inspected, and a Debian-family host running a libpam built without the Debian patch would be read as
if it had it. The basis is recorded in the evidence (`at_include_basis`) so a reader can see it.
On a host that is not Debian-family the lines stay `UNSUPPORTED`, with the reason; when os-release
cannot be read the family is not established and they are `UNSUPPORTED` with that reason - either way
the PAM area is PARTIAL, never a complete stack. An absolute `@include` target is never read: the
event `AT_INCLUDE_ABSOLUTE_NOT_FOLLOWED` makes the stack `INCOMPLETE_STACK` and the area PARTIAL, a
refusal that stays visible as incomplete evidence (`tests/test_pam.py`).

The section records `parser_version` 2. A check-script error during this step - the real store
moved aside without the fresh one a Full Audit needs, then not moved back - was recovered by hand
within minutes, with the real stores' hashes matching the values recorded before; it is recorded in the
evidence (`INCIDENT.txt`) and the script corrected.

## 4. Installed packages: the PRIV criteria and the upgrade from 0.5.0 (2026-11-24)

Packages built from `8131136` (deb `410fd7dc…`, rpm `cf6e79a9…`) on Debian 12 (DEB) and Rocky Linux 9.7
(RPM), evidence `v06-a063-upgrade-20261124`. On each host the real system store was moved aside with
its restore armed first (an exit trap), a fresh store created and verified (root, 0700, empty), and the
real store restored at the end with its hash unchanged.

**Upgrade from the published 0.5.0.** The published 0.5.0 package wrote the store: a Full Audit, an
evaluation with no baseline (its reason in the 0.5.0 wording), a baseline approval, a second Full Audit
and an evaluation against the baseline. The candidate was then installed over it:

- every 0.5.0 file keeps its bytes; at the end only the ledger segment differs, and the 0.5.0 ledger is
  an exact prefix of it (appended, never rewritten); the 0.5.0 `NO_BASELINE` record keeps its wording;
- `sudo isedraf list --all` reads the 0.5.0 runs, both 0.5.0 evaluations and the baseline;
- the report of the 0.5.0 run says `NO_EVALUATION` - "not evaluated by this engine and catalog": an
  evaluation identity binds the engine and the catalogue, so an 8-criteria evaluation is not presented as
  the 10-criteria engine's, and the 0.5.0 artifact stays as it was;
- a new Full Audit and evaluation under 0.6: 10 results, the comparison with the baseline approved
  under 0.5.0 `COMPARED`, accounts, host identity, login policy and SSH `UNCHANGED`, `method_changed`
  false - the PAM parser change does not reach the baseline profile, as the comparability contract says;
- `ISE-PRIV-001` `FAIL` (the lab account's general grant, expected and recorded, D-131) and
  `ISE-PRIV-002` `PASS` on both hosts.

**Terminal sweep, both routes, 80 columns:** 111 of 111 cases as expected on each host (the two new
criteria's `explain` included); the only lines over 80 are the named exception (saved-report paths alone
on their line).

## 5. Installed packages: the SSH and STORAGE criteria (2026-11-24)

Packages built from `92f579e` (deb `eccbd25e…`, rpm `403cd812…`) on Debian 12 (DEB) and Rocky Linux 9.7
(RPM), a Full Audit and an evaluation into a fresh system store (restore armed before the move, real
stores restored unchanged), evidence `v06-a064-install-20261124`. Both hosts gave 14 results; the four
new ones, with the value the snapshot recorded (the same as the host's live `sshd -T` and `findmnt`):

| Criterion | Value recorded | Result |
|---|---|---|
| ISE-SSH-003 | `permitrootlogin without-password` | MANUAL_REVIEW, the value kept as returned |
| ISE-SSH-004 | `hostbasedauthentication no` | PASS |
| ISE-SSH-005 | `hostbasedauthentication no`, `ignorerhosts yes` | NOT_APPLICABLE: the same snapshot recorded host-based authentication off |
| ISE-STORAGE-001 | `/dev/shm` tmpfs, per-mount options `rw,nosuid,nodev` | PASS |

`isedraf explain` of the four: widest line 79 columns.

## 6. Release candidate 0.6.0-rc1 (2026-11-24)

Candidate `bf0c0a6` (tree `e9739022`), evidence `v06-rc1-20261124`. On the build VM, on that exact
commit: `make check`, all gates passed; the full falsification run, 620 executed and detected, 2
declared skips, 0 unexpected non-firing; packages built and their payloads checked (deb `716d2e42…`,
rpm `0253e7cb…`, source commit checked on each host).

**Upgrade from the published 0.5.0, Full Audit, on four platforms.** On each host the real system store
was moved aside with its restore armed first, a fresh store created and verified (root, 0700, empty),
and the real store restored at the end with its hash unchanged. The published 0.5.0 package wrote the
store (a Full Audit, an evaluation with no baseline in the 0.5.0 wording, a baseline approval, a second
Full Audit, an evaluation against the baseline); the candidate was installed over it.

| Check | Debian 12 (DEB) | Ubuntu 24.04 (DEB) | Rocky Linux 9.7 (RPM) | AlmaLinux 9.7 (RPM) |
|---|---|---|---|---|
| 0.5.0 files identical after the upgrade | 40 of 40 | 40 of 40 | 40 of 40 | 40 of 40 |
| At the end: only the ledger differs, the 0.5.0 ledger an exact prefix | yes | yes | yes | yes |
| `sudo isedraf list --all` reads the 0.5.0 runs, evaluations, baseline | exit 0 | exit 0 | exit 0 | exit 0 |
| Report of the 0.5.0 run | `NO_EVALUATION` | `NO_EVALUATION` | `NO_EVALUATION` | `NO_EVALUATION` |
| New Full Audit and evaluation | 14 results | 14 results | 14 results | 14 results |
| Comparison with the 0.5.0 baseline | `COMPARED`, 4 sections `UNCHANGED`, method unchanged, 0 rows | same | same | same |

The 14 results are the same on the four hosts: `ISE-PRIV-001` `FAIL` (the lab account's general grant,
expected, D-131), `ISE-SSH-003` `MANUAL_REVIEW` (`without-password`), `ISE-SSH-005` `NOT_APPLICABLE`
(host-based authentication off), every other one `PASS`.

**The new reports, each against the host's own files.** Report schema 5; the Markdown and HTML reports
carry both additions; `ISE-ACCOUNT-002` keeps its evaluated `PASS` on every host.

| Host | `nullok` beside ISE-ACCOUNT-002 (equal to a `grep` of `/etc/pam.d`) | Maximum password age (equal to field 5 of `/etc/shadow`) |
|---|---|---|
| Debian 12 | `common-auth` line 17 | 31 accounts: 22 at 99999 days, 9 no limit |
| Ubuntu 24.04 | `common-auth` line 17 | 37 accounts: 22 at 99999 days, 15 no limit |
| Rocky Linux 9.7 | `password-auth` line 5, `system-auth` line 5 | 28 accounts: 18 at 99999 days, 10 no limit |
| AlmaLinux 9.7 | `password-auth` line 5, `sssd-shadowutils` line 2, `system-auth` line 5 | 28 accounts: 18 at 99999 days, 10 no limit |

No host had an account whose value was not collected; that state is covered by the tests only.

**Terminal sweep, both routes, 80 columns:** 115 of 115 cases as expected on each of the four hosts,
`isedraf explain` of all 14 criteria included; the only lines over 80 are the named exception (a saved
report's path alone on its line).

**Coverage stated per platform.** Checked from the installed candidate: Debian 12 and Ubuntu 24.04
(DEB), Rocky Linux 9.7 and AlmaLinux 9.7 (RPM), each with a Full Audit. Not run for this candidate: the
other platforms of `PLATFORM_COMPATIBILITY.md`, including AlmaLinux 8.10 (standard audit in earlier
releases).

A check-script defect, recorded with the evidence (`NOTE.txt`): two file-comparison counts were
computed over lists not sorted for `comm`; they were recomputed from the fetched file lists, and the
values above are the recomputed ones.

## 7. Pending, stated

Closed: the visual check of the 14-row `NATIVE_CRITERIA.csv` in a spreadsheet application, by the
owner (2026-11-24); the file is also validated by a parser round trip.


- The authorized_keys fifth fixed operation: the design needs a revision (the allowed-path rule for a
  prefix taken from host configuration) before any implementation.
- The workstation's installed git hooks predate the second owner kit (header line only); the owner re-installs them by
  copying.
