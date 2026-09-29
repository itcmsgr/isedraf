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
