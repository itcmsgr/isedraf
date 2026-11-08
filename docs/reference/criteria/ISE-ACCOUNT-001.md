<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
<!-- GENERATED FILE — DO NOT EDIT MANUALLY.
     Source: lib/isedraf/catalog/native_controls.json
     Regenerate: python3 scripts/docs/criteria_pages.py generate
     `make check` fails when this page and the registry disagree. -->

# ISE-ACCOUNT-001

**GENERATED FILE — DO NOT EDIT MANUALLY**

This page renders the registry record, exactly as `isedraf explain ISE-ACCOUNT-001` does. The record is the only description of the criterion.

```text
ISE-ACCOUNT-001  (version 1, EXPERIMENTAL)

Purpose
  Detect entries in the local account file /etc/passwd, as committed in the snapshot, other than the single root entry, that are assigned UID 0. The conclusion is scoped to that file.

Why it matters
  UID 0 is the identity the kernel treats as root, whatever the account is called. Every additional name mapped to UID 0 is another way to act with full control of the host, and actions taken under it are recorded as UID 0, which makes them hard to attribute to a person.

Check type      local account identity
Severity        high (default_severity; a FAIL finding takes it unchanged)
Applicability   Every Linux host: the local passwd file is a universal source, and the condition does not depend on the host's role or purpose (IQ-070 does not apply). This criterion never yields NOT_APPLICABLE.

Facts required
  - the collection status of the local passwd source (etc/passwd), decided per source by the accounts collector
  - whether a compat INCLUDE directive in etc/passwd widens the identity domain beyond the file
  - for every local passwd record: the exact name bytes and the numeric UID

Dimensions
  declared  the local passwd file as read in the committed snapshot
  resolved  not evaluated: NSS resolution through other services is not observed
  active    not evaluated: running processes are not inspected

How it is evaluated
  Input: the committed, verified snapshot only: sections/accounts.json whose digest matches the snapshot manifest. Nothing is read from the live host and missing evidence is never reconstructed.
  Evidence is sufficient when:
    - sources["etc/passwd"].status is COLLECTED (the per-source status; group and shadow are not required facts, so the section's combined collection_status is not used)
    - remote_identity_inclusion.via_compat_directives_in does not list etc/passwd
    - every local passwd record carries a numeric UID and exact name bytes
  Results:
    NOT_EVALUATED  the evidence is not sufficient (above). This includes PARTIAL, ERROR, NOT_TESTED, truncated or malformed passwd evidence, and a passwd domain widened by an INCLUDE directive. An additional UID-0 record observed in insufficient evidence is reported as an observed fact beside the result, never as FAIL.
    PASS           the evidence is sufficient and exactly one local passwd record has UID 0, and its name is exactly the bytes of "root" (726f6f74).
    FAIL           the evidence is sufficient and the PASS condition does not hold: a UID-0 record whose name is not exactly "root", more than one UID-0 record (including a duplicate root line), or no UID-0 record.
  Never produced: NOT_APPLICABLE, MANUAL_REVIEW
  the result is a function of the committed evidence alone; evaluating the same snapshot again yields the same result and the same evidence references.

Limitations - what a result does not establish
  - Only /etc/passwd is evaluated. A PASS means that, in /etc/passwd as committed, root is the only entry with UID 0. It does not establish that no other UID-0 identity exists: identities from other NSS services (LDAP and other directory services, SSSD, NIS maps), containers, user namespaces or any other identity source are not observed and are not covered.
  - Whether NSS consults the local file is reported beside the result (nss_file_effectiveness) and does not change it.
  - The criterion concerns account entries, not processes: a process running as UID 0 is not observed here.
  - Names are compared as exact bytes; a look-alike name is not root.

Evidence pointers
  manifest.json  /manifest_core/auxiliary_artifacts/sections~1accounts.json  (the digest that binds the accounts section)
  sections/accounts.json  /evidence/sources/etc~1passwd/status  (per-source collection status)
  sections/accounts.json  /evidence/remote_identity_inclusion/via_compat_directives_in  (identity domain widened beyond the file)
  sections/accounts.json  /evidence/local_accounts/<i>/uid  (numeric UID of each record)
  sections/accounts.json  /evidence/local_accounts/<i>/name_bytes_hex  (exact name of each record)
  sections/accounts.json  /evidence/local_accounts/<i>/passwd_line  (line number of each UID-0 record)

Manual verification (read-only)
  Read-only: list the local entries with UID 0, for example with `awk -F: '$3 == 0 {print NR": "$1}' /etc/passwd`, and compare them with the snapshot's records. The command changes nothing.

Remediation guidance (illustrative; ISEDRAF changes nothing)
  Guidance only; ISEDRAF changes nothing. An additional UID-0 entry is usually given its own non-zero UID or removed, after confirming which files, processes and scripts depend on it; changing the UID of an account in use can break ownership and running services, so the change is planned, not immediate.

Baseline state  not available: baseline and delta are v0.4
Delta           not available: baseline and delta are v0.4
```
