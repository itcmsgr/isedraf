<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
<!-- GENERATED FILE — DO NOT EDIT MANUALLY.
     Source: lib/isedraf/catalog/native_controls.json
     Regenerate: python3 scripts/docs/criteria_pages.py generate
     `make check` fails when this page and the registry disagree. -->

# ISE-ACCOUNT-003

**GENERATED FILE — DO NOT EDIT MANUALLY**

This page renders the registry record, exactly as `isedraf explain ISE-ACCOUNT-003` does. The record is the only description of the criterion.

```text
ISE-ACCOUNT-003  (version 1, EXPERIMENTAL)

Purpose
  Detect Duplicate Local UIDs: two or more different local account names in /etc/passwd, as committed, that share one UID. The conclusion is scoped to that file.

Why it matters
  The kernel knows accounts only by UID. Two names with the same UID are the same identity to every file, process and log entry, so actions under one cannot be told apart from actions under the other.

Check type      local account identity
Severity        medium (default_severity; a FAIL finding takes it unchanged)
Applicability   Every Linux host. Role-independent. This criterion never yields NOT_APPLICABLE.

Facts required
  - the collection status of etc/passwd, per source, and whether a compat INCLUDE widens it
  - for every local passwd record: the exact name bytes, the numeric UID and the line

Dimensions
  declared  the local passwd file as read in the committed snapshot
  resolved  not evaluated: NSS resolution through other services is not observed
  active    not evaluated: running processes are not inspected

How it is evaluated
  Input: the committed, verified snapshot only: sections/accounts.json whose digest matches the snapshot manifest. A Standard Audit is sufficient.
  Evidence is sufficient when:
    - sources["etc/passwd"].status is COLLECTED
    - remote_identity_inclusion.via_compat_directives_in does not list etc/passwd
    - every local passwd record carries a numeric UID and exact name bytes
  Results:
    NOT_EVALUATED  the evidence is not sufficient (above). A duplicate seen in insufficient evidence is reported as an observation, never as FAIL.
    FAIL           the evidence is sufficient and two or more records with different exact name bytes have the same UID.
    MANUAL_REVIEW  the evidence is sufficient, no two different names share a UID, but one name appears on more than one line with different UIDs: which line the system resolves is a judgement this criterion does not make, so the lines are listed for a person to decide. Repeated lines of one name with the same UID are listed as an observation and do not change the result.
    PASS           the evidence is sufficient and every UID belongs to exactly one name.
  Never produced: NOT_APPLICABLE
  the result is a function of the committed evidence alone; evaluating the same snapshot again yields the same result and the same evidence references.

Limitations - what a result does not establish
  - Only /etc/passwd is evaluated. A PASS means that, in /etc/passwd as committed, every UID belongs to one name; UIDs from other identity sources are not observed.
  - UID 0 shared by root and another name is also reported by ISE-ACCOUNT-001.
  - Only the local account files are evaluated. Identities from other NSS services (LDAP and other directory services, SSSD, NIS maps), containers or user namespaces are not observed and are not covered.

Evidence pointers
  manifest.json  /manifest_core/auxiliary_artifacts/sections~1accounts.json  (the digest that binds the accounts section)
  sections/accounts.json  /evidence/sources/etc~1passwd/status  (passwd collection status)
  sections/accounts.json  /evidence/remote_identity_inclusion/via_compat_directives_in  (identity domain widened beyond the file)
  sections/accounts.json  /evidence/local_accounts/<i>/uid  (numeric UID of each record)
  sections/accounts.json  /evidence/local_accounts/<i>/name_bytes_hex  (exact name of each record)
  sections/accounts.json  /evidence/local_accounts/<i>/passwd_line  (line of each record)

Manual verification (read-only)
  Read-only: `cut -d: -f3 /etc/passwd | sort | uniq -d` lists UIDs that appear more than once. The command changes nothing.

Remediation guidance (illustrative; ISEDRAF changes nothing)
  Guidance only; ISEDRAF changes nothing. Duplicate UIDs are usually resolved by giving each account its own UID, after re-owning the files of the moved account; the change affects file ownership and running processes, so it is planned.

Baseline state  not available: baseline and delta are v0.4
Delta           not available: baseline and delta are v0.4
```
