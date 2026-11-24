<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
<!-- GENERATED FILE — DO NOT EDIT MANUALLY.
     Source: lib/isedraf/catalog/native_controls.json
     Regenerate: python3 scripts/docs/criteria_pages.py generate
     `make check` fails when this page and the registry disagree. -->

# ISE-SSH-003

**GENERATED FILE — DO NOT EDIT MANUALLY**

This page renders the registry record, exactly as `isedraf explain ISE-SSH-003` does. The record is the only description of the criterion.

```text
ISE-SSH-003  (version 1, EXPERIMENTAL)
Global SSH Root Login Setting
Introduced in ISEDRAF 0.6.0. Needs at least a Full Audit: sshd -T is run only
  by a Full Audit (resolve_sshd_effective_config_v1); that is necessary, not
  sufficient.

Purpose
  Global SSH Root Login Setting: the global value of PermitRootLogin that sshd
  -T reports, as committed. The conclusion concerns the global configuration
  only, not every connection.

Why it matters
  Root is the account every attacker tries first, and a successful login as
  root needs no further step to control the host. Letting root log in over the
  network with a password exposes that account to password guessing; most
  administration can be done by logging in as a person and then elevating.

Check type      effective daemon configuration
Severity        high (default_severity; a FAIL finding takes it unchanged)
Applicability   Every Linux host where the Full Audit ran sshd -T.
                Role-independent. This criterion never yields NOT_APPLICABLE.

Facts required
  - the collection status of the resolved dimension: the coverage entry whose
    operation_id is resolve_sshd_effective_config_v1
  - the resolved setting permitrootlogin and its value

Dimensions
  declared  not evaluated
  resolved  sshd -T without a connection context: the global effective
            configuration
  active    not evaluated: no connection is attempted

How it is evaluated
  Input: the committed, verified snapshot only: sections/ssh.json whose digest
    matches the snapshot manifest. sshd -T is run only by a Full Audit.
  Evidence is sufficient when:
    - the one coverage entry whose operation_id is
      resolve_sshd_effective_config_v1 has status COLLECTED
    - exactly one RESOLVED_SETTING record has keyword permitrootlogin
  Results:
    NOT_EVALUATED  the resolved dimension is not COLLECTED (every Standard
                   Audit, a refused or failed sshd -T), the setting is not
                   reported exactly once, or its value is not one this
                   criterion knows.
    PASS           the evidence is sufficient and the value is no: root cannot
                   log in over SSH by any method.
    FAIL           the evidence is sufficient and the value is yes: root can
                   log in over SSH with any enabled method, a password
                   included.
    MANUAL_REVIEW  the evidence is sufficient and the value is
                   prohibit-password or its older name without-password (root
                   can log in with a key or another method that is not a
                   password), or forced-commands-only (root can log in only
                   with a public key whose authorized_keys entry forces a
                   command). The value sshd -T returned is reported unchanged,
                   with what access remains.
  Never produced: NOT_APPLICABLE
  the result is a function of the committed evidence alone; evaluating the same
  snapshot again yields the same result and the same evidence references.

Limitations - what a result does not establish
  - Global effective configuration only: values that a Match block sets for
    some users, groups or addresses are not resolved, and a per-connection
    value may differ.
  - Whether root has a password or authorized keys at all is not part of this
    criterion; a FAIL states what the SSH daemon permits.
  - Under MANUAL_REVIEW, which keys or forced commands root accepts is in
    root's authorized_keys, which the Full Audit does not read today.

Evidence pointers
  - manifest.json
      /manifest_core/auxiliary_artifacts/sections~1ssh.json
      the digest that binds the ssh section
  - sections/ssh.json
      /evidence/provenance/coverage/<i>/status
      status of the coverage entry whose operation_id is
      resolve_sshd_effective_config_v1
  - sections/ssh.json
      /evidence/provenance/coverage/<i>/operation_id
      the fixed operation that selects that coverage entry
  - sections/ssh.json
      /evidence/records/<i>/kind
      RESOLVED_SETTING marks an sshd -T line
  - sections/ssh.json
      /evidence/records/<i>/keyword
      the setting name
  - sections/ssh.json
      /evidence/records/<i>/value
      the setting value

Manual verification (read-only)
  Read-only, as root: `sshd -T | grep -i '^permitrootlogin'` prints the global
  value. The command changes nothing.

Remediation guidance (illustrative; ISEDRAF changes nothing)
  Guidance only; ISEDRAF changes nothing. PermitRootLogin is usually set to no,
  or to prohibit-password where key-based root access is needed, after
  confirming that another administrator account can log in and elevate; keep a
  session open while changing sshd_config and test with sshd -t.

Baseline state  belongs to an evidence store, not to a criterion:
                `isedraf evaluate` (or `sudo isedraf evaluate`) compares the
                latest run with the store's approved baseline
Delta           per run, in the Baseline comparison of the evaluation and of
                the report (since 0.4.0)
```
