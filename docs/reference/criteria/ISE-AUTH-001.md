<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
<!-- GENERATED FILE — DO NOT EDIT MANUALLY.
     Source: lib/isedraf/catalog/native_controls.json
     Regenerate: python3 scripts/docs/criteria_pages.py generate
     `make check` fails when this page and the registry disagree. -->

# ISE-AUTH-001

**GENERATED FILE — DO NOT EDIT MANUALLY**

This page renders the registry record, exactly as `isedraf explain ISE-AUTH-001` does. The record is the only description of the criterion.

```text
ISE-AUTH-001  (version 1, EXPERIMENTAL)

Purpose
  Declared login.defs Password Hashing Method: evaluate the ENCRYPT_METHOD value declared in /etc/login.defs, as committed, against a narrowly defined legacy-algorithm policy (MD5 and DES are legacy), without claiming the effective PAM password hashing behaviour.

Why it matters
  ENCRYPT_METHOD is the hashing method that the shadow-utils tools reading login.defs use for new passwords. Declaring MD5 or DES there means passwords set by those tools are stored with a legacy, fast-to-crack hash.

Check type      password hashing policy
Severity        medium (default_severity; a FAIL finding takes it unchanged)
Applicability   Every Linux host with /etc/login.defs. Role-independent. This criterion never yields NOT_APPLICABLE.

Facts required
  - the collection status of the LOGIN_DEFS source family
  - the ENCRYPT_METHOD records declared in /etc/login.defs: key, value, retention and malformed flag

Dimensions
  declared  the ENCRYPT_METHOD value declared in /etc/login.defs as committed
  resolved  not evaluated: the method pam_unix or another tool applies is not observed
  active    not evaluated: no password is set

How it is evaluated
  Input: the committed, verified snapshot only: sections/loginpolicy.json whose digest matches the snapshot manifest. A Standard Audit is sufficient.
  Evidence is sufficient when:
    - every provenance source of family LOGIN_DEFS has status COLLECTED
    - exactly one well-formed ENCRYPT_METHOD record of family LOGIN_DEFS exists, with retention RETAIN_VALUE
  Results:
    NOT_EVALUATED  the evidence is not sufficient: a LOGIN_DEFS source not COLLECTED, no ENCRYPT_METHOD declared (the built-in default differs between distributions), more than one ENCRYPT_METHOD (conflicting), a malformed record, or a value not retained.
    FAIL           the evidence is sufficient and the value is exactly MD5 or DES.
    PASS           the evidence is sufficient and the value is exactly SHA256 or SHA512: the declared method is not a legacy one. This is not a claim that the system as a whole uses a secure password hashing policy.
    NOT_EVALUATED  the value is YESCRYPT or BCRYPT, whose support depends on the shadow-utils and libxcrypt build of the platform, which the committed evidence does not record; or any other value, including a known method spelled in another case, which never passes.
  Never produced: NOT_APPLICABLE, MANUAL_REVIEW
  the result is a function of the committed evidence alone; evaluating the same snapshot again yields the same result and the same evidence references.

Limitations - what a result does not establish
  - The criterion evaluates the declared login.defs setting only. pam_unix options, other tools and distribution defaults decide the method actually applied when a password is changed; they are not evaluated.
  - A PASS does not mean that the system uses a secure password hashing policy, only that the declared ENCRYPT_METHOD is not MD5 or DES.
  - YESCRYPT and BCRYPT give NOT_EVALUATED: platform support for them is not in the committed evidence.

Evidence pointers
  manifest.json  /manifest_core/auxiliary_artifacts/sections~1loginpolicy.json  (the digest that binds the loginpolicy section)
  sections/loginpolicy.json  /evidence/provenance/sources/<i>/family  (the source family)
  sections/loginpolicy.json  /evidence/provenance/sources/<i>/status  (the collection status of each source)
  sections/loginpolicy.json  /evidence/records/<i>/family  (the record family)
  sections/loginpolicy.json  /evidence/records/<i>/key  (the declared key)
  sections/loginpolicy.json  /evidence/records/<i>/value  (the declared value)
  sections/loginpolicy.json  /evidence/records/<i>/retention  (whether the value is retained verbatim)
  sections/loginpolicy.json  /evidence/records/<i>/malformed  (whether the line was read exactly)

Manual verification (read-only)
  Read-only: `grep -E '^[[:space:]]*ENCRYPT_METHOD' /etc/login.defs` prints the declared value. The command changes nothing.

Remediation guidance (illustrative; ISEDRAF changes nothing)
  Guidance only; ISEDRAF changes nothing. Declaring ENCRYPT_METHOD SHA512 (or a stronger method the platform supports) in /etc/login.defs affects passwords set later by the tools that read it; check pam_unix options separately, as they decide the method for passwd changes.

Baseline state  not available: baseline and delta are v0.4
Delta           not available: baseline and delta are v0.4
```
