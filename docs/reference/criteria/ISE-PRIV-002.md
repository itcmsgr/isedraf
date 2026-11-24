<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
<!-- GENERATED FILE — DO NOT EDIT MANUALLY.
     Source: lib/isedraf/catalog/native_controls.json
     Regenerate: python3 scripts/docs/criteria_pages.py generate
     `make check` fails when this page and the registry disagree. -->

# ISE-PRIV-002

**GENERATED FILE — DO NOT EDIT MANUALLY**

This page renders the registry record, exactly as `isedraf explain ISE-PRIV-002` does. The record is the only description of the criterion.

```text
ISE-PRIV-002  (version 1, EXPERIMENTAL)
Authentication Disabled by sudo Defaults
Introduced in ISEDRAF 0.6.0. Needs at least a Full Audit: /etc/sudoers and its
  includes are read only by a Full Audit (read_sudoers_graph_v1); that is
  necessary, not sufficient.

Purpose
  Authentication Disabled by sudo Defaults: Defaults settings in the declared
  local sudo policy, as committed, that turn authentication off (!authenticate)
  for every rule or for a scope. The conclusion concerns the declared policy
  only.

Why it matters
  Defaults !authenticate removes the password prompt from every rule in its
  scope at once, so a single line can make every sudo rule passwordless - often
  far more than the person who wrote it intended.

Check type      local sudo delegation
Severity        high (default_severity; a FAIL finding takes it unchanged)
Applicability   Every Linux host with a local sudo policy. This criterion never
                yields NOT_APPLICABLE: an /etc/sudoers that is not found gives
                NOT_EVALUATED.

Facts required
  - the collection status of the declared sudo policy read by the Full Audit's
    fixed operation read_sudoers_graph_v1, the status of /etc/sudoers in it,
    whether every include was read, and whether any line could not be read
  - for every Defaults record: its scope type (global, user, run-as, host,
    command), its scope as written, its options with their negation, and its
    file and line
  - the names of the declared aliases

Dimensions
  declared  the local sudo policy files as read in the committed snapshot
  resolved  not evaluated: aliases and the precedence between scope types are
            not resolved
  active    not evaluated: sudo is not run

How it is evaluated
  Input: the committed, verified snapshot only: sections/sudo.json whose digest
    matches the snapshot manifest. The sudo policy is read only by a Full Audit
    (read_sudoers_graph_v1); a Standard Audit records it NOT_TESTED.
  Evidence is sufficient when:
    - the coverage entry for /etc/sudoers with operation_id
      read_sudoers_graph_v1 has status COLLECTED
    - the sudo section is COLLECTED, its include_status is COLLECTED and its
      malformed_count is 0, with no UNSUPPORTED record
  Results:
    NOT_EVALUATED  the evidence is not sufficient: every Standard Audit, a
                   refused or partial read, an unread include, an unsupported
                   line, and an /etc/sudoers the Full Audit did not find
                   (reason SUDOERS_ABSENT).
    FAIL           the evidence is sufficient and some scope ends with
                   !authenticate. A scope is identified by its type and one
                   member as written (the global scope has one member;
                   Defaults:alice,bob names the members alice and bob). Its
                   settings are ordered by line within one file; settings of
                   one scope in several files are ordered only when they agree,
                   because the position of an include directive is not in the
                   evidence. A scope whose member is an alias or a negation is
                   never a FAIL. The result names each scope and its
                   declarations.
    MANUAL_REVIEW  the evidence is sufficient, no scope is a FAIL, and some
                   scope is undecided: !authenticate set on a scope whose
                   member is an alias or a negation, or settings of one scope
                   that disagree and lie in several files.
    PASS           the evidence is sufficient, no scope ends with !authenticate
                   and none is undecided, including a policy that never sets
                   authenticate.
  Never produced: NOT_APPLICABLE
  the result is a function of the committed evidence alone; evaluating the same
  snapshot again yields the same result and the same evidence references.

Limitations - what a result does not establish
  - Declared Defaults only. Scopes are compared as written: an alias used as a
    scope is not resolved, and a member written twice under different scopes of
    one type is compared as one member.
  - Precedence between scope types is not computed: a global !authenticate that
    a Defaults:alice authenticate re-enables for one user is still a FAIL for
    the global scope.
  - The order of settings in different files is not established from the
    evidence; settings that disagree across files give MANUAL_REVIEW.
  - rootpw, targetpw and runaspw are not assessed; NOPASSWD tags on rules are
    ISE-PRIV-001.
  - Only the local sudo policy files are read; LDAP and SSSD sudo rules are
    not.

Evidence pointers
  - manifest.json
      /manifest_core/auxiliary_artifacts/sections~1sudo.json
      the digest that binds the sudo section
  - sections/sudo.json
      /collection_status
      the collection status of the declared sudo policy
  - sections/sudo.json
      /evidence/provenance/coverage/<i>/status
      status of the coverage entry for /etc/sudoers read by
      read_sudoers_graph_v1
  - sections/sudo.json
      /evidence/provenance/coverage/<i>/operation_id
      the fixed operation that selects that coverage entry
  - sections/sudo.json
      /evidence/provenance/coverage/<i>/source
      the file of that coverage entry (/etc/sudoers)
  - sections/sudo.json
      /evidence/provenance/coverage/<i>/access_outcome
      why /etc/sudoers was not read, when it was not
  - sections/sudo.json
      /evidence/provenance/include_status
      whether every include was read
  - sections/sudo.json
      /evidence/provenance/malformed_count
      lines that could not be read
  - sections/sudo.json
      /evidence/records/<i>/kind
      DEFAULTS marks a Defaults setting
  - sections/sudo.json
      /evidence/records/<i>/source_path
      the file of the setting
  - sections/sudo.json
      /evidence/records/<i>/source_line
      the line of the setting
  - sections/sudo.json
      /evidence/records/<i>/scope_type
      global, user, run-as, host or command
  - sections/sudo.json
      /evidence/records/<i>/scope
      the scope as written
  - sections/sudo.json
      /evidence/records/<i>/options
      the options with their negation

Manual verification (read-only)
  Read-only, as root: `sudo -V` prints the defaults sudo was built with and the
  Defaults in force for the invoking user; `visudo -c` checks the files.
  Neither changes anything.

Remediation guidance (illustrative; ISEDRAF changes nothing)
  Guidance only; ISEDRAF changes nothing. A Defaults !authenticate is usually
  removed, or replaced by NOPASSWD on the specific rules that need it, after
  confirming which automation depends on it; edit with visudo.

Baseline state  belongs to an evidence store, not to a criterion:
                `isedraf evaluate` (or `sudo isedraf evaluate`) compares the
                latest run with the store's approved baseline
Delta           per run, in the Baseline comparison of the evaluation and of
                the report (since 0.4.0)
```
