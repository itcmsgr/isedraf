<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Changelog

Status: IMPLEMENTED
Implements: D-88, §40

All notable changes to ISEDRAF are recorded here. Format follows Keep a Changelog; versioning follows
Semantic Versioning once a release exists. `VERSION` is the single source of the current version.

## [Unreleased]

## [0.6.0] - 2026-11-24

ISEDRAF 0.6: native audit coverage. Fourteen native criteria in five families, a catalogue of every
criterion as a CSV file, PAM `@include` read on Debian-family hosts, and `nullok` and the maximum
password age per account in the report. The 0.6.0-rc1 entry below lists every change; nothing was
added after 0.6.0-rc1 but the version.

### Upgrading
- From 0.5.0: existing runs, evaluations, baselines and the ledger are kept with their bytes;
  nothing is approved, re-evaluated or deleted automatically. A run evaluated by 0.5.0 reports
  `NO_EVALUATION` until it is evaluated again; a baseline approved under 0.5.0 still applies.

### Tested
- 0.6.0-rc1: `make check`; the full falsification run, 620 injections detected; the installed
  packages upgraded from the published 0.5.0 with a Full Audit on Debian 12, Ubuntu 24.04, Rocky
  Linux 9.7 and AlmaLinux 9.7 (every 0.5.0 file unchanged, the 0.5.0 baseline comparing
  `UNCHANGED`, the new report content equal to the hosts' own files); every command and case on
  both routes in an 80-column terminal (115 cases each).

## [0.6.0-rc1] - 2026-11-24

ISEDRAF 0.6: native audit coverage. Fourteen native criteria in five families (six new: two over
the local sudo policy, three over the global SSH server configuration, the first over the mount
table), a catalogue of every criterion as a CSV file, PAM `@include` read on Debian-family hosts,
and two recorded settings in the report.

### Upgrading
- Existing runs, evaluations, baselines and the ledger are kept with their bytes and still read;
  the ledger is only appended to. Nothing is approved, re-evaluated or deleted automatically.
- An evaluation binds the engine and the criteria catalogue: after the upgrade, `isedraf report` of
  a run evaluated by 0.5.0 says `NO_EVALUATION` until `isedraf evaluate` (or `sudo isedraf
  evaluate`) runs again. The 0.5.0 evaluation stays in the store unchanged.
- A baseline approved under 0.5.0 still applies: the PAM parser change does not reach the baseline
  profile, so an unchanged host compares `UNCHANGED`.

### Added
- `docs/reference/NATIVE_CRITERIA.csv`: every native criterion this release delivers, one row each -
  title, description, lifecycle, criterion version and the release that introduced it, severity,
  check type, evidence sections, collection requirements, applicability, result meanings,
  limitations and where it is explained. Generated from the registry; UTF-8, opens in a
  spreadsheet. Installed with the offline documentation, with one page per criterion (D-130).
- `isedraf explain` shows each criterion's title, the release that introduced it and the collection
  route it needs at least.
- Two native criteria over the declared local sudo policy, read by a Full Audit (D-131):
  `ISE-PRIV-001` (every command as root without authentication) and `ISE-PRIV-002`
  (authentication disabled by `Defaults !authenticate`). Both say `MANUAL_REVIEW` when an alias, a
  named host, a negation or the order of files decides the answer, and `NOT_EVALUATED` when the
  policy was not fully read - including an `/etc/sudoers` that is not found.
- Four more native criteria (D-132): `ISE-SSH-003` (the global `PermitRootLogin`: `no` passes, `yes`
  fails, `prohibit-password` and `forced-commands-only` need a person), `ISE-SSH-004` (host-based
  authentication off globally), `ISE-SSH-005` (with host-based authentication on, users' `.rhosts` and
  `.shosts` ignored; not applicable when it is off) and `ISE-STORAGE-001` (`/dev/shm` mounted `nosuid`
  in the host's mount table). All four need a Full Audit.
- Two recorded settings in the report, neither a criterion (D-132): beside `ISE-ACCOUNT-002`, each
  `auth` line that loads `pam_unix` with `nullok`, with its service and file - the criterion keeps
  the result its evaluation recorded; and the maximum password age of each local account, keeping
  "no limit" (an empty field), a number of days as written (99999 included) and "not collected"
  apart. The JSON report's schema version is 5 (`pam_nullok`, `password_max_age`).

### Changed
- A new evaluation with no approved baseline gives the reason `NO_BASELINE: no approved baseline
  was in force in this store when the run was evaluated, so nothing was compared`. Earlier
  evaluations keep their bytes and their wording and read the same way.
- PAM: on Debian and Ubuntu, `@include common-auth` and the other `@include` lines are read as
  what libpam does with them - every line of the target, of every type - so the PAM area of a
  Debian-family host is no longer PARTIAL because of them. Elsewhere they are recorded as
  unsupported, with the reason; an absolute target is not read. The PAM section's parser version is
  2; earlier runs keep their recorded version and stay readable.

## [0.5.0] - 2026-11-20

ISEDRAF 0.5: operator experience. Help on both routes, bash completion, a summary after every
run, `isedraf list` and `sudo isedraf list`, refusals that say why, what was written and what
to run next, a free-space check before every run (exit 68), ledger recovery after an
interrupted write (`STORE-016`), and terminal text within 80 columns on every command. The
entries of the release candidates below (0.5.0-rc1 to 0.5.0-rc4) list every change; nothing was
added after 0.5.0-rc4 but the version.

### Upgrading
- From 0.4.0: existing runs, evaluations, baselines and the ledger are kept and still verify;
  nothing is approved, recovered or deleted automatically. Bare `isedraf` exits 0 with the start
  page (it was 64); exit code 68 (`INSUFFICIENT_SPACE`) is new.

### Tested
- 0.5.0-rc4: `make check`; the full falsification run, 601 injections detected; the installed
  packages on Ubuntu 24.04, Debian 12 and AlmaLinux 9.7, every command and case on both routes
  in an 80-column terminal (109 cases each), with exit codes and store checks.
- 0.5.0-rc1: the upgrade from the published 0.4.0 on Rocky Linux 9.7, Debian 12 and AlmaLinux
  8.10; ledger recovery and the free-space refusal in the lab on both routes. Running out of
  space during a commit or a recovery is covered by unit tests only.

## [0.5.0-rc4] - 2026-11-20

Internal release candidate: the terminal text of every command fits 80 columns, on both routes
(`explain`, `help --all`, `list`, the identity, inventory and evaluate views, argument errors and
refusals). An identifier, path or digest is never split; a long one stands alone on its line.
The Markdown, HTML and JSON reports keep their own formats. A coverage test of every command and
case holds the rule.

## [0.5.0-rc3] - 2026-11-20

Internal release candidate. From the rc2 acceptance in an 80-column terminal: the audit
summary's host-identity, development-store and privilege lines wrap too (the host id, a
hash, gets its own line and is never split). The README shows the ISEDRAF logo; its two lines
spell out the name, and the product description is unchanged (`docs/assets/LOGO.md`).

## [0.5.0-rc2] - 2026-11-20

Internal release candidate. From the rc1 acceptance: four messages wrap at 80 columns like the
rest of the human output - the ledger-recovery notice, the user-route and Full Audit evaluate
refusals, and the Full Audit free-space refusal; reason tokens, identifiers and paths stay whole.
Exit codes are unchanged.

## [0.5.0-rc1] - 2026-11-17

ISEDRAF 0.5: operator experience. A start page and help on both routes, bash completion, a
summary after every run, `isedraf list`, refusals that say why and what next, a free-space
check before every run, and ledger recovery after an interrupted write (`STORE-016`).

### Upgrading
- Existing runs, evaluations, baselines and the ledger are kept and still verify; a ledger
  written by 0.4 is segment 1 of the segmented ledger. Nothing is approved, recovered or
  deleted automatically.
- Bare `isedraf` now exits 0 with the start page (it was 64). New exit code 68
  (`INSUFFICIENT_SPACE`).

### Added
- `isedraf --help` lists every command grouped by purpose (collect evidence, evaluate and
  understand, approve a reference, view results; developer commands last), with the workflow
  to start from. `isedraf <command> --help` states what the command does, who runs it, what it
  writes, its exit codes and complete examples (v0.5, `D-129`).
- A missing argument now explains what to give: `isedraf explain` lists the installed criterion
  IDs; `isedraf baseline approve` points to `sudo isedraf baseline approve` for production
  baselines. The exit code is unchanged (64).
- `docs/reference/CLI.md`, the command reference, generated from the same command definitions
  as the help, and installed with the offline documentation.
- Bash completion, installed by both packages at
  `/usr/share/bash-completion/completions/isedraf`: commands, each command's own options and
  the installed criterion IDs. Generated from the command definitions; it never reads an
  evidence store or offers a snapshot ID. Loaded where the `bash-completion` package is
  installed; nothing changes without it.
- `isedraf` with no arguments, and `isedraf help`, print a start page: Standard Audit and Full
  Audit, the workflow with complete commands, and baseline approval as an explicit decision.
  `isedraf help --all` lists every command, grouped; `isedraf help <command>` explains one.
- Under `sudo` or root, `sudo isedraf`, `sudo isedraf help`, `sudo isedraf --help` and `sudo
  isedraf --version` print the same help from the installed definitions, exit 0, and read no
  evidence, open no store and start nothing (`AUTH-019` as amended for v0.5).

- A free-space check before every run (`isedraf audit`, `isedraf identity`, `sudo isedraf
  audit`): when the filesystem holding the evidence store has too little room for the run and
  a ledger recovery record, the run is refused with exit 68 (`INSUFFICIENT_SPACE`) before
  anything is collected or written, stating the space available and needed. A disk that fills
  during a run is reported with the same code, and the run is not committed. Nothing is ever
  deleted to make room.

- `isedraf list` shows what your evidence store holds: committed runs (with their collection
  time and class, and which one the baseline approved), evaluations with their result counts,
  the baseline, and saved reports with their absolute paths; `--all` for every entry. It
  reads committed metadata only and writes nothing. Snapshot directories the ledger does not
  record are counted, never listed as runs. `sudo isedraf list` lists the system store
  read-only: Full Audit runs, the baseline and evaluation identities, from the ledger and
  directory names; it opens no evidence and writes nothing.
- Refusals say the reason in plain words first, keep the reason token (for example
  `BASELINE_CLASS_NOT_ADMITTED`) whole, say whether anything was written and give the next
  command. The refusal under `sudo` also lists `sudo isedraf list` and shows how to export a
  Full Audit report privately. An account entered through `sudo -iu` is told why it is
  refused and to log in directly. Where `/usr/bin/python3` is missing (a stock AlmaLinux 8),
  the refusal says ISEDRAF runs there as the normal user only.
- Evaluation reasons and the Full Audit commit line wrap at 80 columns; identifiers, paths
  and reason tokens are never split.

- Ledger recovery (`STORE-016`): every ledger write checks that the whole record was written.
  If an earlier write was interrupted (a crash, or a disk that filled), the next audit or
  approval keeps the damaged segment byte for byte, and a new segment continues the ledger with
  a `ledger_recovered` record that names it and the hash of the incomplete bytes. Only an
  interrupted last record is recovered; an earlier damaged record or a broken chain is refused
  and nothing is written. `report`, `list` and `evaluate` never recover: each refuses an
  unrecovered ledger, writes nothing (`evaluate` writes evaluations, never the ledger) and says
  which command recovers it.

### Changed
- The report (Markdown and HTML) opens with what a reader needs first: the coverage of each
  area, the native criteria results and the baseline comparison. The target, the evidence
  detail with its digests, and the limitations follow. The JSON model is unchanged.
- The install instructions say why the `./` in `apt install ./...` and `dnf install ./...`
  matters, and the Evidence model explains why the evidence stores are private.
- `sudo isedraf audit` shows the same summary as a standard audit, naming the system store;
  the launcher then states the commit. `sudo isedraf evaluate` and `sudo isedraf baseline
  approve` end with the next command.
- Baseline approval, on both routes, first shows what is being approved - the run and its
  collection time, the store, the profile and every required section with its status - and
  that approval records accepted state without establishing that the host is secure, before
  anything is written.
- `isedraf report --save` prints the saved file's absolute path and how to view it. The
  Report guide shows how to export a Full Audit report privately, without overwriting a file.
- `isedraf audit` ends with a summary: whether the run was committed complete or
  incomplete, coverage counts, each area not fully collected with its reason (and, for the
  areas a Full Audit fixed operation reads, that `sudo isedraf audit` reads them), where the
  run is stored, the next commands, and what exit 2 means. `audit`, `identity`, `evaluate`,
  `baseline approve` and `inventory` start with a short header: version, command, and for
  evidence the store, snapshot and collection time from the committed run. `--json` output
  is unchanged.
- Refusals of the store, the run lock and engine failures on the user route say whether
  anything was written and, where one applies, the next command.
- `isedraf` with no arguments exits 0 with the start page; it was a usage error (64). It
  collects, approves and writes nothing. Invalid commands and arguments still exit 64;
  `isedraf help` naming an unknown command exits 64 and lists the valid ones.
- The refusal under `sudo` or root lists what runs there one command per line and points to
  `sudo isedraf help`.
- `isedraf baseline approve` without a snapshot ID, and its `--help`, describe the two separate
  contexts: a development (DEV) store, where a named run is approved, and the system store,
  where `sudo isedraf baseline approve` approves its latest Full Audit run. Approving under
  sudo never turns a personal-store run into production evidence.
- Development builds are versioned `0.5.0-dev`. Their packages carry the source commit in the
  package version (`0.5.0~dev.<commit time>.g<commit>` for the DEB; for the RPM, version
  `0.5.0` with release `0.<label>.<commit time>.g<commit>`, label `dev`), ordered below any
  0.5.0 prerelease or release, and both
  packages install `/usr/share/doc/isedraf/SOURCE`, naming the commit they were built from.

## [0.4.0] - 2026-11-13

ISEDRAF 0.4: approved baselines. `sudo isedraf baseline approve` approves the latest
complete Full Audit run as the baseline of the system store; each later evaluation records,
section by section, whether the host's recorded state is unchanged, MODIFIED (to review)
or NOT_COMPARABLE, and the report shows it. Approved means accepted, not secure.

### Added
- `isedraf baseline approve <SDS-id>` (v0.4, development stores only for now): explicitly
  approves one complete committed run as baseline `BL-000001` against the packaged profile
  `v0.4-default-1` (host identity, accounts, SSH, login policy). An incomplete run, or a run of
  any other store, is refused with exit 65 and a named reason; nothing is written.
- `isedraf evaluate` compares against the approved baseline when one is in force, after
  verifying it (exit 5 when it does not verify): one MODIFIED row per changed section,
  interpreted REVIEW_REQUIRED, or NOT_COMPARABLE with a reason. Its other exit codes are
  unchanged. With no baseline, its output is unchanged.
- `sudo isedraf baseline approve`: approves the latest complete Full Audit run as the
  production baseline of the system store. It names no snapshot; an incomplete run is
  refused with exit 65. `sudo isedraf evaluate` then compares against it.
- The report's "Baseline comparison" part (Markdown, HTML, and `baseline_comparison` in
  JSON; report schema 4): the comparison exactly as the evaluation recorded it.

### Changed
- Exit codes 5 (the baseline does not verify) and 65 (approval refused) are now reachable.
- Under sudo, ISEDRAF runs `audit`, `report`, `evaluate` and `baseline approve`; the
  refusal message for anything else names all four.
- An evaluation of a store with a baseline names the baseline in its identity, so it is a
  different evaluation from one made before the approval.

### Upgrading
- Existing runs, the ledger and earlier evaluations are kept and still verify. A store
  without a baseline evaluates exactly as before. Nothing is approved automatically.

### Fixed
- In 0.4.0-rc1, reports showed the run's host identifier, collection time, run identifier
  and run mode as empty while still reporting the evidence as verified; they now show the
  values of the reported run.

### Tested
- The release candidate was installed over the published 0.3.0 by the package manager on
  hosts with existing evidence stores, on Debian 12, Ubuntu 24.04, Rocky Linux 9.7 and
  AlmaLinux 9.7 (Full Audit, SELinux enforcing on the last two) and on AlmaLinux 8.10
  (standard audit; Full Audit refused as unsupported), all on x86_64. The upgrade changed
  no stored file; every earlier run still verified. On the four Full Audit platforms a
  complete run was approved, an unchanged run gave no change, a controlled change gave one
  section to review, and a run made incomplete on purpose was refused with the blocking
  section named. The report fix was checked on Debian 12 and Rocky Linux 9.7.
- Not tested: ARM64, and upgrades from 0.1.x or 0.2.x directly to 0.4.0.

## [0.3.0] - 2026-11-08

ISEDRAF 0.3: native criteria. `isedraf evaluate` reads one committed, verified run and
evaluates it against eight ISEDRAF-authored criteria; it never collects. Each result is PASS,
FAIL, MANUAL_REVIEW or NOT_EVALUATED, with the evidence it rests on, and is committed as a
regenerable evaluation beside the run. `isedraf explain <criterion>` shows what a criterion
checks and what it does not establish. The criteria are EXPERIMENTAL and are not a
compliance verdict.

### Added
- `isedraf evaluate` (user store) and `sudo isedraf evaluate` (the Full Audit store; the
  evaluation itself runs unprivileged).
- `isedraf explain <criterion>`, and a page per criterion in `docs/reference/criteria/`.
- Eight criteria: ISE-ACCOUNT-001 (UID 0 only for root), ISE-ACCOUNT-002 (empty shadow
  password fields), ISE-ACCOUNT-003 (duplicate UIDs), ISE-ACCOUNT-004 (MD5 password
  hashes), ISE-ACCOUNT-005 (duplicate GIDs), ISE-AUTH-001 (declared login.defs hashing
  method), ISE-SSH-001 (global PermitEmptyPasswords), ISE-SSH-002 (global StrictModes).
  Criteria that need /etc/shadow or `sshd -T` give NOT_EVALUATED on a standard audit.
- The report shows the committed evaluation of the reported run, if there is one.

### Changed
- `sudo isedraf report` checks that its renderer runs reduced, as the Full Audit engine
  does, and refuses otherwise.
- The rpm ships the same runtime files as the deb; it no longer installs `exitcodes.json`
  and `runtime-imports.allow`, which nothing at runtime reads.

### Upgrading
- The package upgrades 0.2.0 in place; existing runs are kept and still verify. A run
  made by 0.2.0 can be evaluated by 0.3.0.

### Tested
- The release candidate was installed over 0.2.0 by the package manager (`dpkg -i`,
  `rpm -Uvh`) on hosts with existing evidence stores, on Debian 12, Ubuntu 24.04, Rocky
  Linux 9.7 and AlmaLinux 9.7 (Full Audit, SELinux enforcing on the last two) and on
  AlmaLinux 8.10 (standard audit; Full Audit refused as unsupported), all on x86_64. The
  upgrade changed no stored file; every earlier run still verified; runs made by 0.2.0
  were evaluated, and evaluating them again gave identical results; new runs were audited,
  evaluated and reported.
- Not tested: ARM64, and upgrades from 0.1.x directly to 0.3.0.

## [0.2.0] - 2026-10-12

ISEDRAF 0.2: Full Audit. `sudo isedraf audit` collects, in a sandboxed systemd
unit, evidence a standard audit cannot read - `/etc/shadow`, the sudo policy files, the SSH
server configuration files and the global effective SSH configuration - through four fixed
privileged operations, while the engine that collects and interprets runs as the unprivileged
`isedraf` account with no capabilities. `sudo isedraf report` renders the result read-only.
The standard audit is unchanged apart from its exit codes 66 and 67.

### Upgrading
- The package upgrades 0.1.2 in place. The evidence in your own store is kept and still
  verifies; reports of 0.1.x runs show no run mode. The package now declares the `isedraf`
  system account and creates `/var/lib/isedraf` only when nothing exists there.
- A refused evidence store now exits 67 and a held lock 66; both exited 64 before.

### Tested
- The release candidate was installed, upgraded from 0.1.2, reinstalled, removed and run
  on Debian 12, Ubuntu 24.04, Rocky Linux 9.7 and AlmaLinux 9.7 (Full Audit, with SELinux
  enforcing on the last two, and after a reboot) and on AlmaLinux 8.10 (standard audit;
  Full Audit refused as unsupported), all on x86_64.
- Not tested: ARM64, and upgrades from 0.1.0 or 0.1.1 directly to 0.2.0.

### Changed
- Each committed snapshot now records its run mode, `STANDARD_AUDIT` or `FULL_AUDIT`.
  It is part of the snapshot manifest and never of host state,
  so host-state hashes are unchanged. Snapshots from 0.1.x have no run mode recorded
  and still verify (D-124).
- Exit codes: a run that finds another ISEDRAF run holding the lock now exits `66`, and
  an evidence store that cannot be used (wrong owner or mode, unsuitable storage, cannot
  be prepared) exits `67`. Both previously exited `64`, which stays the code for usage
  and engine errors. Nothing is collected or written in either case (D-124).
- Under `sudo` or as root, every command except `isedraf audit` and `isedraf report` is
  refused with exit `70` and the message "Under sudo or root, ISEDRAF runs only `sudo isedraf
  audit` (Full Audit) and `sudo isedraf report` (its report). Run other ISEDRAF commands as
  your normal user." `sudo isedraf audit` starts the Full Audit route on Debian 12, Ubuntu
  24.04, Rocky Linux 9 and AlmaLinux 9. Its first fixed privileged operation,
  `read_shadow_v1`, reads `/etc/shadow` for the accounts section;
  the evidence records that source as acquired by that operation, and every other source
  as read by the engine itself (D-124).
- Full Audit: the sudo section is acquired by the second fixed privileged
  operation, `read_sudoers_graph_v1`, within its fixed surface - `/etc/sudoers`, the listing of
  `/etc/sudoers.d` and each entry directly in it, a symlink observed and never followed. The
  engine builds the include graph from what the operation returned; an include outside that
  surface, a symlinked or non-regular entry, or a listing that could not be made makes the
  section PARTIAL, never absent. No capability is added (AUTH-029).
- Full Audit: the declared sshd configuration is acquired by the third
  fixed privileged operation, `read_sshd_declared_config_v1` - `/etc/ssh/sshd_config`, the
  listing of `/etc/ssh/sshd_config.d` and each entry directly in it, a symlink observed and
  never followed. The engine applies sshd's Include and Match grammar; an include outside
  that surface, at any depth, is read by the engine as itself and recorded as such, or is
  NOT_TESTED. sshd is never run. No capability is added (AUTH-030).
- Full Audit: the ssh section also records the global effective sshd
  configuration, from the fourth fixed privileged operation, `resolve_sshd_effective_config_v1`,
  which runs `/usr/sbin/sshd -T` with no other argument. It is the configuration sshd computes
  when no connection is known: Match blocks are not applied, so Match-dependent values are
  reported as not resolved, and the evidence and the report say so. Only a successful run with
  output yields settings; a failure, an empty or malformed output is ERROR or NOT_TESTED and
  nothing is derived from it. The output is kept byte-for-byte, and the order of a repeated
  setting such as `listenaddress` is kept, because it can change what sshd listens on. The
  standard route never runs sshd. No capability is added (AUTH-031).
- Full Audit: `sudo isedraf audit` now relays the audit's output through pipes
  it owns instead of handing your terminal, pipe or file to systemd-run. Redirecting the
  output to a file had disrupted systemd on AlmaLinux 9. If the output cannot be written (a
  reader that stopped early, a full disk), the audit still completes, one line on stderr says
  so, and the exit code still describes the audit (AUTH-020).
- Full Audit: an interrupted `sudo isedraf audit` is never committed afterwards.
  SIGTERM, SIGHUP or Ctrl-C stops the audit unit; if it had not yet committed its snapshot, nothing
  is committed, no staging is left, and the exit status is 128 plus the signal. If the snapshot
  was already committed, it stays valid, the exit code is the audit's, and one line on stderr says
  so. Stopping the unit with `systemctl stop`, or its time limit, no longer reports success
  (AUTH-020).
- Full Audit: `sudo isedraf report` (optionally `--json` or `--html`) renders the
  report of the latest committed Full Audit run, read-only. A root launcher reads the store's ledger
  and that run's snapshot files and hands them to a renderer running as the unprivileged `isedraf`
  account, which verifies the ledger chain and every hash before rendering and says what it
  verified. Nothing is written to the store; `--save` and `--profile` are refused under sudo. The
  report shows the run mode (AUTH-032).
- Full Audit reports: the SSH area shows its declared configuration, its global
  effective configuration (`sshd -T`, global only) and its Match-dependent values each with its own
  status, in Markdown as in HTML; the report states how each source was acquired, from the run's
  evidence-limits record; it says Full Audit has no operation for other users' `authorized_keys`;
  and the HTML privilege line reads `FULL_AUDIT`. Standard reports are unchanged (AUTH-009).
- The packages now declare the `isedraf` system account (through a systemd sysusers
  file; no home, no login shell, never removed on uninstall) and create
  `/var/lib/isedraf`, owned by root with mode 0700, for Full Audit evidence - only when
  nothing exists at that path. An existing file, link or directory there is never changed,
  replaced or removed by a package; Full Audit refuses a non-conforming one (D-124).

### Fixed
- sudo: the `@include` and `@includedir` directives (the sudo 1.9 spelling, the default on
  Debian and Ubuntu) were parsed as malformed policy lines, so a readable default sudoers
  was reported PARTIAL with a malformed line that is not there. They are directives now,
  like `#include` and `#includedir` (IQ-058).
- sudo, collection under `--root`: a symlink in the collection root's `sudoers.d` was
  followed, and an absolute one resolved against the machine running the collection
  rather than the root given. It is now observed as a symlink and not followed, and the
  section is PARTIAL (`SYMLINK_NOT_FOLLOWED`) (IQ-057).
- Full Audit: active mounts and the inventory's filesystem list are no
  longer taken from the Full Audit sandbox's own mount table, which is not the host's.
  They come from PID 1's mount table, which the engine reads with no added privilege;
  when it cannot be read they are NOT_TESTED / PARTIAL (`HOST_MOUNT_TABLE_UNREADABLE`),
  never the sandbox's table. Filesystem space is reported only where the path inside the
  sandbox is shown to be the same device as the host's mount; otherwise the storage
  subdomain is PARTIAL (`FILESYSTEM_IDENTITY_NOT_PROVEN`) (IQ-053, IQ-055). On an SELinux-enforcing host
  whose `chronyc` would need a domain transition that no-new-privileges forbids, Full
  Audit does not run it and records `MAC_DOMAIN_TRANSITION_UNAVAILABLE` (IQ-053, IQ-054).

## [0.1.2] - 2026-10-08

A correction release for 0.1.1. It makes the evidence say what was not observed:
incomplete collection is reported as such, and each run records its evidence limits.
It adds no privileged collection.

### Changed
- Each audit section now records which collector produced it - collector, collector
  version and parser version - so that a change in ISEDRAF can be told apart from a change
  on the host. The section format version is 2 (IQ-042).
- `isedraf audit` now writes `coverage/evidence_limits.json`, the Evidence Limits Manifest
  (schema 2): for every source each section tried to read, what happened, who read it and
  what that means for interpreting the evidence, and an explicit entry for any section
  that reported nothing. It is bound into the snapshot manifest and never into host state
  (IQ-042).
- `isedraf report` shows an "Evidence limitations" section: for each source the run
  could not observe completely, its section, source, status, recorded reason and what
  that means for interpreting the evidence. A run without an evidence-limits record says
  its coverage is not established. The report format version is 2 (IQ-042).

### Fixed
- Inventory time: when `chronyc` is present and `chronyc tracking` fails, the time
  subdomain is now PARTIAL with a recorded reason (`HELPER_FAILED`) instead of COLLECTED
  with the time source, stratum and offset silently missing (IQ-054).
- sudo: an `/etc/sudoers.d` that exists but cannot be listed was treated as an empty
  directory, so a readable `/etc/sudoers` was reported as the complete sudo policy. The
  section is now `PARTIAL`, the listing is recorded as not observed, and no absence of
  further policy is claimed (IQ-046).
- login policy: when every login-policy file existed but none could be read, the section
  said the sources were absent; it now says they were unreadable. A fragment directory
  such as `pwquality.conf.d` that exists but cannot be listed is no longer dropped
  silently: the section is `PARTIAL` and the listing is recorded as not observed (IQ-046).
- inventory: a file the inventory could not read because of permissions is now attributed
  to privilege rather than reported as an I/O error, and a mounted filesystem whose space
  could not be measured is no longer left out silently: the storage subdomain is `PARTIAL`
  and names the mount (IQ-046).
- PAM: when `/etc/pam.d` is absent or cannot be listed, the evidence now records the
  listing itself as not found or refused, instead of carrying no coverage record at all
  (IQ-046).
- SSH authorized keys: when the SSH server configuration could not be read, the section no
  longer says that the configuration declares no `AuthorizedKeysFile`; it says the SSH
  evidence was incomplete. An absent configuration is reported as before (IQ-046).

### Upgrading
- The package upgrades 0.1.1 in place and keeps the evidence in your store. Snapshots
  committed by 0.1.1 are not rewritten and still verify; they carry no evidence-limits
  record, so a report of one of them says its coverage is not established. A new audit
  records the corrected observations and the evidence limits.

## [0.1.1] - 2026-10-06

A correction release for 0.1.0. It changes one collector and nothing else.

### Fixed
- SSH authorized keys: a key file the collector could not examine - typically because
  another user's home directory is not traversable - was reported as absent, which
  allowed the section to be complete and to claim that no keys exist. It is now reported
  as not observed: the section is `PARTIAL` and no absence is claimed. A file that really
  does not exist is still reported as absent (IQ-044).

### Upgrading
- The package upgrades 0.1.0 in place and keeps the evidence in your store. Snapshots
  committed by 0.1.0 are not rewritten; a new audit records the corrected observation.

## [0.1.0] - 2026-09-28

The first release of ISEDRAF.

### Added
- Unprivileged Linux host evidence collection with one command, `isedraf audit`, across
  ten domains: host and platform inventory, local accounts and groups, NSS configuration,
  hostname, sudo, SSH server configuration, PAM, login policy, mounts and SSH authorized
  keys.
- A user-mode evidence store at `$XDG_STATE_HOME/isedraf` or `~/.local/state/isedraf`,
  private to the user (mode 0700). A store on a network or unknown filesystem is refused
  before anything is written.
- One committed evidence run per audit: canonical JSON, hash-bound, recorded in a
  hash-chained ledger and verified after every commit.
- `isedraf report`: a report of the latest committed run - Markdown, JSON, or a static HTML
  page - rendered from committed evidence only.
- DEB and RPM packages for the system Python (3.6 or later), with no compiled code and no
  third-party runtime module.

### Upgrading from a pre-release
- The package upgrades 0.1.0-alpha1 in place and keeps the evidence in your store.
- Running `sudo isedraf` is refused, as before, and no longer leaves Python bytecode in
  the installed package directory.
- Pre-release cleanup: If you previously ran 0.1.0-alpha1 with sudo, Python may have left
  unowned bytecode under `/usr/lib/isedraf`. After uninstalling ISEDRAF and confirming the
  package is no longer installed, the remaining ISEDRAF bytecode/directory may be removed
  manually.

### Limitations
- This release does not run with elevated privilege. Facts that need root, such as
  `/etc/shadow` and sudoers, are reported NOT_TESTED: not observed, never passed.
- PARTIAL means some evidence could not be collected. It does not mean the host is secure
  or insecure.
- There are no pass/fail judgements and no comparison between runs. A run with no
  observed problem does not show that a host is uncompromised.
- Evidence is protected by filesystem permissions. It is not protected against a local
  administrator.

### Comparability
- First release: there is no earlier normalized state to compare with, and no baseline to
  rebind.

<!-- Entry template:
## [0.1.0] - YYYY-MM-DD
### Added / Changed / Deprecated / Removed / Fixed / Security
- Description. (REQ-ID)

### Comparability
- State whether this release alters normalized state for an unchanged host, and whether
  `isedraf baseline rebind` is required. Required for every release (D-45, D-56).
-->
