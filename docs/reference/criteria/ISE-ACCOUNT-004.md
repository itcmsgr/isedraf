<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
<!-- GENERATED FILE — DO NOT EDIT MANUALLY.
     Source: lib/isedraf/catalog/native_controls.json
     Regenerate: python3 scripts/docs/criteria_pages.py generate
     `make check` fails when this page and the registry disagree. -->

# ISE-ACCOUNT-004

**GENERATED FILE — DO NOT EDIT MANUALLY**

This page renders the registry record, exactly as `isedraf explain ISE-ACCOUNT-004` does. The record is the only description of the criterion.

```text
ISE-ACCOUNT-004  (version 1, EXPERIMENTAL)

Purpose
  Detect Legacy MD5 Password Hash Schemes: local /etc/shadow entries, as committed, whose stored hash uses an MD5-based scheme (MD5_CRYPT or SUN_MD5). The conclusion concerns the stored scheme only.

Why it matters
  MD5-based password hashes are fast to compute, so a stolen /etc/shadow is much easier to crack. A stored MD5 hash is a weakness even on a locked account, because the hash itself is what an attacker would take.

Check type      local credential storage
Severity        medium (default_severity; a FAIL finding takes it unchanged)
Applicability   Every Linux host with local accounts. Role-independent. This criterion never yields NOT_APPLICABLE.

Facts required
  - the collection status of etc/passwd and etc/shadow, per source, and whether a compat INCLUDE widens either
  - for every local account with a shadow record: the redacted password state (content, hash_scheme)
  - whether shadow records exist without a passwd account (orphan_shadow_records), whose state is not recorded

Dimensions
  declared  the local shadow file as read in the committed snapshot
  resolved  not evaluated: the hashing policy configured for new passwords is not observed
  active    not evaluated

How it is evaluated
  Input: the committed, verified snapshot only: sections/accounts.json whose digest matches the snapshot manifest. etc/shadow is collected only by a Full Audit.
  Evidence is sufficient when:
    - sources["etc/passwd"].status and sources["etc/shadow"].status are COLLECTED
    - remote_identity_inclusion.via_compat_directives_in lists neither etc/passwd nor etc/shadow
  Results:
    NOT_EVALUATED  the evidence is not sufficient (above); or no MD5 scheme is seen but some state cannot be classified: content OTHER, hash_scheme OTHER_RECOGNIZED_FORMAT, an account whose shadow relation is not PRESENT, or an orphan shadow record, whose state is not recorded. OTHER is never read as safe and never as DES.
    FAIL           the evidence is sufficient and at least one shadow password state has content HASH_PRESENT and hash_scheme MD5_CRYPT or SUN_MD5, locked or not.
    PASS           the evidence is sufficient, every account has a PRESENT shadow record, there is no orphan shadow record, and every HASH_PRESENT state names one of BCRYPT, SHA256_CRYPT, SHA512_CRYPT, SCRYPT, YESCRYPT or GOST_YESCRYPT. EMPTY and DISABLED_TOKEN fields carry no hash and do not affect this criterion.
  Never produced: NOT_APPLICABLE, MANUAL_REVIEW
  the result is a function of the committed evidence alone; evaluating the same snapshot again yields the same result and the same evidence references.

Limitations - what a result does not establish
  - Only MD5_CRYPT and SUN_MD5 are detected. Traditional DES crypt has no recognised prefix and is recorded as content OTHER, which gives NOT_EVALUATED, not FAIL (IQ-075).
  - The scheme of the stored hash is evaluated, not the policy for new passwords; a FAIL does not claim that the account can log in.
  - No password, hash or salt is stored or shown; only the bounded scheme name the collector records.
  - Only the local account files are evaluated. Identities from other NSS services (LDAP and other directory services, SSSD, NIS maps), containers or user namespaces are not observed and are not covered.

Evidence pointers
  manifest.json  /manifest_core/auxiliary_artifacts/sections~1accounts.json  (the digest that binds the accounts section)
  sections/accounts.json  /evidence/sources/etc~1passwd/status  (passwd collection status)
  sections/accounts.json  /evidence/sources/etc~1shadow/status  (shadow collection status)
  sections/accounts.json  /evidence/remote_identity_inclusion/via_compat_directives_in  (identity domain widened beyond the files)
  sections/accounts.json  /evidence/local_accounts/<i>/shadow_record  (shadow relation of each account)
  sections/accounts.json  /evidence/local_accounts/<i>/shadow/password_state  (redacted password state of each account)
  sections/accounts.json  /evidence/local_accounts/<i>/name_bytes_hex  (exact name of each account)
  sections/accounts.json  /evidence/orphan_shadow_records  (shadow lines without a passwd account)

Manual verification (read-only)
  Read-only, as root: `awk -F: '$2 ~ /^!?\$(1|md5)\$/ {print NR": "$1}' /etc/shadow` lists entries with an MD5-based hash. The command prints names and line numbers only, never the hash.

Remediation guidance (illustrative; ISEDRAF changes nothing)
  Guidance only; ISEDRAF changes nothing. An MD5 hash is replaced only when the password is next set; confirming the system's default scheme for new passwords and asking the account owner to change the password removes it.

Baseline state  not available: baseline and delta are v0.4
Delta           not available: baseline and delta are v0.4
```
