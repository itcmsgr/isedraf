<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
<!-- GENERATED FILE — DO NOT EDIT MANUALLY.
     Source: lib/isedraf/catalog/native_controls.json
     Regenerate: python3 scripts/docs/criteria_pages.py generate
     `make check` fails when this page and the registry disagree. -->

# ISE-ACCOUNT-002

**GENERATED FILE — DO NOT EDIT MANUALLY**

This page renders the registry record, exactly as `isedraf explain ISE-ACCOUNT-002` does. The record is the only description of the criterion.

```text
ISE-ACCOUNT-002  (version 1, EXPERIMENTAL)

Purpose
  Detect Empty Local Shadow Password Fields: local accounts whose /etc/shadow password field, as committed, is empty and not locked. The conclusion is an observation of that field only.

Why it matters
  An empty password field records that no password is set for the account. Whether a login without a password is then possible depends on the authentication stack (PAM, SSH), which this criterion does not evaluate; the observed empty field is still a weakness worth knowing about.

Check type      local credential storage
Severity        high (default_severity; a FAIL finding takes it unchanged)
Applicability   Every Linux host with local accounts. Role-independent. This criterion never yields NOT_APPLICABLE.

Facts required
  - the collection status of etc/passwd and etc/shadow, per source
  - whether a compat INCLUDE directive widens either source
  - for every local account: its shadow relation (PRESENT, ABSENT_FROM_COLLECTED_SOURCE, SOURCE_NOT_COLLECTED) and, when PRESENT, the redacted password state (lock_prefix, content)

Dimensions
  declared  the local passwd and shadow files as read in the committed snapshot
  resolved  not evaluated: which field the authentication stack consults is not observed
  active    not evaluated: login attempts are not made

How it is evaluated
  Input: the committed, verified snapshot only: sections/accounts.json whose digest matches the snapshot manifest. etc/shadow is collected only by a Full Audit (read_shadow_v1); a Standard Audit records it NOT_TESTED.
  Evidence is sufficient when:
    - sources["etc/passwd"].status and sources["etc/shadow"].status are COLLECTED
    - remote_identity_inclusion.via_compat_directives_in lists neither etc/passwd nor etc/shadow
    - every local account's shadow relation is PRESENT
  Results:
    NOT_EVALUATED  the evidence is not sufficient (above). An account whose shadow relation is ABSENT_FROM_COLLECTED_SOURCE is NOT_EVALUATED, because the field the system then consults is the /etc/passwd password field, which the committed evidence does not carry (IQ-077). An empty unlocked field seen in insufficient evidence is reported as an observation, never as FAIL.
    FAIL           the evidence is sufficient and at least one account's shadow password state has content EMPTY and lock_prefix LOCK_PREFIX_ABSENT.
    PASS           the evidence is sufficient and no account's shadow password state has content EMPTY with lock_prefix LOCK_PREFIX_ABSENT. A locked field (leading '!') and the DISABLED_TOKEN ('*') are not empty fields.
  Never produced: NOT_APPLICABLE, MANUAL_REVIEW
  the result is a function of the committed evidence alone; evaluating the same snapshot again yields the same result and the same evidence references.

Limitations - what a result does not establish
  - The conclusion concerns the /etc/shadow password field as committed. It does not establish whether a login without a password is possible: PAM and SSH configuration are not evaluated here.
  - The /etc/passwd password field is not in the committed evidence (IQ-077); an account without a shadow record is therefore not evaluated.
  - No password, hash or salt is stored or shown; only the redacted state the collector records.
  - Only the local account files are evaluated. Identities from other NSS services (LDAP and other directory services, SSSD, NIS maps), containers or user namespaces are not observed and are not covered.

Evidence pointers
  manifest.json  /manifest_core/auxiliary_artifacts/sections~1accounts.json  (the digest that binds the accounts section)
  sections/accounts.json  /evidence/sources/etc~1passwd/status  (passwd collection status)
  sections/accounts.json  /evidence/sources/etc~1shadow/status  (shadow collection status)
  sections/accounts.json  /evidence/remote_identity_inclusion/via_compat_directives_in  (identity domain widened beyond the files)
  sections/accounts.json  /evidence/local_accounts/<i>/shadow_record  (shadow relation of each account)
  sections/accounts.json  /evidence/local_accounts/<i>/shadow/password_state  (redacted password state of each account)
  sections/accounts.json  /evidence/local_accounts/<i>/name_bytes_hex  (exact name of each account)
  sections/accounts.json  /evidence/local_accounts/<i>/passwd_line  (line of each account)

Manual verification (read-only)
  Read-only, as root: `awk -F: '$2 == "" {print NR": "$1}' /etc/shadow` lists entries whose password field is empty. The command changes nothing and prints no password material.

Remediation guidance (illustrative; ISEDRAF changes nothing)
  Guidance only; ISEDRAF changes nothing. An account with an empty field is usually locked or given a password, after confirming which logins or automated jobs depend on it.

Baseline state  not available: baseline and delta are v0.4
Delta           not available: baseline and delta are v0.4
```
