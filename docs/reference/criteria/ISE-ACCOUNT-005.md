<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
<!-- GENERATED FILE — DO NOT EDIT MANUALLY.
     Source: lib/isedraf/catalog/native_controls.json
     Regenerate: python3 scripts/docs/criteria_pages.py generate
     `make check` fails when this page and the registry disagree. -->

# ISE-ACCOUNT-005

**GENERATED FILE — DO NOT EDIT MANUALLY**

This page renders the registry record, exactly as `isedraf explain ISE-ACCOUNT-005` does. The record is the only description of the criterion.

```text
ISE-ACCOUNT-005  (version 1, EXPERIMENTAL)

Purpose
  Detect Duplicate Local GIDs: two or more different group names in /etc/group, as committed, that share one GID. The conclusion is scoped to that file.

Why it matters
  The kernel knows groups only by GID. Two group names with the same GID are one group to every file and process, so membership and access granted under one name silently apply under the other, which blurs who was meant to have access.

Check type      local account identity
Severity        low (default_severity; a FAIL finding takes it unchanged)
Applicability   Every Linux host. Role-independent. This criterion never yields NOT_APPLICABLE.

Facts required
  - the collection status of etc/group, per source, and whether a compat INCLUDE widens it
  - for every local group record: the exact name bytes, the numeric GID and the line

Dimensions
  declared  the local group file as read in the committed snapshot
  resolved  not evaluated: NSS resolution through other services is not observed
  active    not evaluated: process credentials are not inspected

How it is evaluated
  Input: the committed, verified snapshot only: sections/accounts.json whose digest matches the snapshot manifest. A Standard Audit is sufficient (/etc/group is world-readable).
  Evidence is sufficient when:
    - sources["etc/group"].status is COLLECTED
    - remote_identity_inclusion.via_compat_directives_in does not list etc/group
    - every local group record carries a numeric GID and exact name bytes
  Results:
    NOT_EVALUATED  the evidence is not sufficient (above). A duplicate seen in insufficient evidence is reported as an observation, never as FAIL.
    FAIL           the evidence is sufficient and two or more records with different exact name bytes have the same GID.
    MANUAL_REVIEW  the evidence is sufficient, no two different names share a GID, but one name appears on more than one line with different GIDs, both lines kept in the evidence: which line the system resolves needs a person. Repeated identical entries are listed as observations and do not change the result.
    PASS           the evidence is sufficient and every GID belongs to exactly one name.
  Never produced: NOT_APPLICABLE
  the result is a function of the committed evidence alone; evaluating the same snapshot again yields the same result and the same evidence references.

Limitations - what a result does not establish
  - Only /etc/group is evaluated. A PASS means that, in /etc/group as committed, every GID belongs to one name; groups from LDAP, SSSD, NIS or other NSS services are not observed.
  - A shared GID is an identity and accountability problem; on its own it is not evidence of a privilege escalation.
  - Group membership and group passwords are not evaluated.

Evidence pointers
  manifest.json  /manifest_core/auxiliary_artifacts/sections~1accounts.json  (the digest that binds the accounts section)
  sections/accounts.json  /evidence/sources/etc~1group/status  (group collection status)
  sections/accounts.json  /evidence/remote_identity_inclusion/via_compat_directives_in  (identity domain widened beyond the file)
  sections/accounts.json  /evidence/local_groups/<i>/gid  (numeric GID of each record)
  sections/accounts.json  /evidence/local_groups/<i>/name_bytes_hex  (exact name of each record)
  sections/accounts.json  /evidence/local_groups/<i>/group_line  (line of each record)

Manual verification (read-only)
  Read-only: `cut -d: -f3 /etc/group | sort | uniq -d` lists GIDs that appear more than once. The command changes nothing.

Remediation guidance (illustrative; ISEDRAF changes nothing)
  Guidance only; ISEDRAF changes nothing. Duplicate GIDs are usually resolved by giving each group its own GID, after re-owning the files of the moved group; the change affects file access, so it is planned.

Baseline state  not available: baseline and delta are v0.4
Delta           not available: baseline and delta are v0.4
```
