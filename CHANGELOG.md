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
