<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
<!-- GENERATED FILE — DO NOT EDIT MANUALLY.
     Source: lib/isedraf/catalog/native_controls.json
     Regenerate: python3 scripts/docs/criteria_pages.py generate
     `make check` fails when this page and the registry disagree. -->

# ISE-SSH-001

**GENERATED FILE — DO NOT EDIT MANUALLY**

This page renders the registry record, exactly as `isedraf explain ISE-SSH-001` does. The record is the only description of the criterion.

```text
ISE-SSH-001  (version 1, EXPERIMENTAL)

Purpose
  SSH Global PermitEmptyPasswords Configuration: the global value of PermitEmptyPasswords that sshd -T reports, as committed. The conclusion concerns the global configuration only, not every connection.

Why it matters
  When PermitEmptyPasswords is yes, the SSH server accepts a password login for an account whose password is empty. With no, it refuses such logins globally.

Check type      effective daemon configuration
Severity        high (default_severity; a FAIL finding takes it unchanged)
Applicability   Hosts where the Full Audit could run sshd -T. Role-independent. This criterion never yields NOT_APPLICABLE: an sshd absent at the fixed path /usr/sbin/sshd does not prove that no SSH server exists.

Facts required
  - the collection status of the resolved dimension: the coverage entry whose operation_id is resolve_sshd_effective_config_v1
  - the resolved setting permitemptypasswords and its value
  - declared DIRECTIVE records with keyword permitemptypasswords and scope MATCH, as observations only

Dimensions
  declared  observations only: Match-scoped declarations are listed, never resolved
  resolved  sshd -T without a connection context: the global effective configuration
  active    not evaluated: no connection is attempted

How it is evaluated
  Input: the committed, verified snapshot only: sections/ssh.json whose digest matches the snapshot manifest. sshd -T is run only by a Full Audit (resolve_sshd_effective_config_v1).
  Evidence is sufficient when:
    - the one coverage entry whose operation_id is resolve_sshd_effective_config_v1 has status COLLECTED
    - exactly one RESOLVED_SETTING record has keyword permitemptypasswords
  Results:
    NOT_EVALUATED  the resolved dimension is not COLLECTED (including TOOL_ABSENT, a refused or failed sshd -T, and every Standard Audit), or the setting is not reported exactly once. The reason names the coverage status.
    PASS           the evidence is sufficient and the value is no. The result concerns the global configuration.
    FAIL           the evidence is sufficient and the value is yes.
    NOT_EVALUATED  the evidence is sufficient but the value is neither yes nor no.
  Never produced: NOT_APPLICABLE, MANUAL_REVIEW
  the result is a function of the committed evidence alone; evaluating the same snapshot again yields the same result and the same evidence references.

Limitations - what a result does not establish
  - sshd -T is run without a connection context, so Match blocks are not applied. A global no does not establish that every connection refuses empty passwords; Match-scoped PermitEmptyPasswords declarations are listed as observations and never change the result.
  - Only the sshd at /usr/sbin/sshd is observed; another SSH server (another path, a different implementation) is not.
  - Whether any account has an empty password is ISE-ACCOUNT-002, not this criterion.

Evidence pointers
  manifest.json  /manifest_core/auxiliary_artifacts/sections~1ssh.json  (the digest that binds the ssh section)
  sections/ssh.json  /evidence/provenance/coverage/<i>/status  (status of the coverage entry whose operation_id is resolve_sshd_effective_config_v1)
  sections/ssh.json  /evidence/provenance/coverage/<i>/operation_id  (the fixed operation that selects that coverage entry)
  sections/ssh.json  /evidence/records/<i>/kind  (RESOLVED_SETTING marks an sshd -T line; DIRECTIVE a declared one)
  sections/ssh.json  /evidence/records/<i>/keyword  (the setting name)
  sections/ssh.json  /evidence/records/<i>/value  (the setting value)
  sections/ssh.json  /evidence/records/<i>/scope  (the scope of a declared setting (Match observations))

Manual verification (read-only)
  Read-only, as root: `sshd -T | grep -i '^permitemptypasswords'` prints the global value; `sshd -T -C user=<name>,host=<host>,addr=<address>` shows the value for one connection context. Neither command changes anything.

Remediation guidance (illustrative; ISEDRAF changes nothing)
  Guidance only; ISEDRAF changes nothing. Setting PermitEmptyPasswords no in sshd_config, including inside any Match block that sets it, and reloading sshd refuses such logins; check first that no automated access depends on them.

Baseline state  not available: baseline and delta are v0.4
Delta           not available: baseline and delta are v0.4
```
