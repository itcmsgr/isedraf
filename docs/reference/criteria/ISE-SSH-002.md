<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
<!-- GENERATED FILE — DO NOT EDIT MANUALLY.
     Source: lib/isedraf/catalog/native_controls.json
     Regenerate: python3 scripts/docs/criteria_pages.py generate
     `make check` fails when this page and the registry disagree. -->

# ISE-SSH-002

**GENERATED FILE — DO NOT EDIT MANUALLY**

This page renders the registry record, exactly as `isedraf explain ISE-SSH-002` does. The record is the only description of the criterion.

```text
ISE-SSH-002  (version 1, EXPERIMENTAL)

Purpose
  Global SSH StrictModes Configuration: the global value of StrictModes that sshd -T reports, as committed. The conclusion concerns the global configuration only.

Why it matters
  With StrictModes yes, sshd refuses a login when the user's home directory or key files can be written by others, so a key cannot be planted through loose permissions. With no, those checks are skipped.

Check type      effective daemon configuration
Severity        medium (default_severity; a FAIL finding takes it unchanged)
Applicability   Hosts where the Full Audit could run sshd -T. Role-independent. This criterion never yields NOT_APPLICABLE: an sshd absent at /usr/sbin/sshd does not prove that no SSH server exists.

Facts required
  - the collection status of the resolved dimension: the coverage entry whose operation_id is resolve_sshd_effective_config_v1
  - the resolved setting strictmodes and its value

Dimensions
  declared  not evaluated
  resolved  sshd -T without a connection context: the global effective configuration
  active    not evaluated: no connection is attempted

How it is evaluated
  Input: the committed, verified snapshot only: sections/ssh.json whose digest matches the snapshot manifest. sshd -T is run only by a Full Audit.
  Evidence is sufficient when:
    - the one coverage entry whose operation_id is resolve_sshd_effective_config_v1 has status COLLECTED
    - exactly one RESOLVED_SETTING record has keyword strictmodes
  Results:
    NOT_EVALUATED  the resolved dimension is not COLLECTED (including TOOL_ABSENT, a refused or failed sshd -T, and every Standard Audit), or the setting is not reported exactly once.
    PASS           the evidence is sufficient and the value is yes. The result concerns the global configuration.
    FAIL           the evidence is sufficient and the value is no.
    NOT_EVALUATED  the evidence is sufficient but the value is neither yes nor no.
  Never produced: NOT_APPLICABLE, MANUAL_REVIEW
  the result is a function of the committed evidence alone; evaluating the same snapshot again yields the same result and the same evidence references.

Limitations - what a result does not establish
  - sshd -T is run without a connection context; the result concerns the global configuration, and connection-specific state is not established by it.
  - Only the sshd at /usr/sbin/sshd is observed.
  - The permissions of individual home directories and key files are not evaluated here.

Evidence pointers
  manifest.json  /manifest_core/auxiliary_artifacts/sections~1ssh.json  (the digest that binds the ssh section)
  sections/ssh.json  /evidence/provenance/coverage/<i>/status  (status of the coverage entry whose operation_id is resolve_sshd_effective_config_v1)
  sections/ssh.json  /evidence/provenance/coverage/<i>/operation_id  (the fixed operation that selects that coverage entry)
  sections/ssh.json  /evidence/records/<i>/kind  (RESOLVED_SETTING marks an sshd -T line)
  sections/ssh.json  /evidence/records/<i>/keyword  (the setting name)
  sections/ssh.json  /evidence/records/<i>/value  (the setting value)

Manual verification (read-only)
  Read-only, as root: `sshd -T | grep -i '^strictmodes'` prints the global value. The command changes nothing.

Remediation guidance (illustrative; ISEDRAF changes nothing)
  Guidance only; ISEDRAF changes nothing. Setting StrictModes yes in sshd_config and reloading sshd restores the permission checks; first make sure no account depends on loose home or key permissions.

Baseline state  not available: baseline and delta are v0.4
Delta           not available: baseline and delta are v0.4
```
