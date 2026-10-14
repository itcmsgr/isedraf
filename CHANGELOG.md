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
