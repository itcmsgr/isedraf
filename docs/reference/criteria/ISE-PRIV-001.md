<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
<!-- GENERATED FILE — DO NOT EDIT MANUALLY.
     Source: lib/isedraf/catalog/native_controls.json
     Regenerate: python3 scripts/docs/criteria_pages.py generate
     `make check` fails when this page and the registry disagree. -->

# ISE-PRIV-001

**GENERATED FILE — DO NOT EDIT MANUALLY**

This page renders the registry record, exactly as `isedraf explain ISE-PRIV-001` does. The record is the only description of the criterion.

```text
ISE-PRIV-001  (version 1, EXPERIMENTAL)
Every Command as Root Without Authentication
Introduced in ISEDRAF 0.6.0. Needs at least a Full Audit: /etc/sudoers and its
  includes are read only by a Full Audit (read_sudoers_graph_v1); that is
  necessary, not sufficient.

Purpose
  Every Command as Root Without Authentication: rules in the declared local
  sudo policy, as committed, that let a principal other than root run every
  command, as root, on every host, without authenticating. The conclusion
  concerns the declared policy only.

Why it matters
  sudo exists so that a person proves who they are before acting as root. A
  rule that grants every command as root without a password removes that step:
  anyone who can act as that account - including a process or an attacker that
  has taken it over - becomes root with no further check, and nothing ties the
  action to a person who authenticated.

Check type      local sudo delegation
Severity        high (default_severity; a FAIL finding takes it unchanged)
Applicability   Every Linux host with a local sudo policy. This criterion never
                yields NOT_APPLICABLE: an /etc/sudoers that is not found gives
                NOT_EVALUATED, because the absence of sudo is not established
                by the absence of the file alone.

Facts required
  - the collection status of the declared sudo policy read by the Full Audit's
    fixed operation read_sudoers_graph_v1, the status of /etc/sudoers in it,
    whether every include was read, and whether any line could not be read
  - for every user specification (SPEC): its principals with their kind and
    negation, its host, its run-as users and groups, and per command the
    command, its negation and the tags in force
  - the names of the declared aliases
  - every Defaults setting of runas_default, with its scope: a rule without a
    run-as list runs as the runas_default user (root by default)

Dimensions
  declared  the local sudo policy files as read in the committed snapshot
  resolved  not evaluated: aliases, group membership, host matching and sudo's
            last-match rule are not resolved
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
                   (reason SUDOERS_ABSENT: with no declared policy to read, the
                   absence of sudo is not established by this alone).
    FAIL           the evidence is sufficient and some SPEC is decisive: its
                   host is ALL (not negated); it runs as root (a run-as user
                   list naming ALL or root, none negated or an alias, or no
                   run-as list while runas_default is root: never set, or set
                   only globally and only to root - sudoers(5): a rule without
                   a run-as list runs as the runas_default user, root by
                   default; when runas_default is set globally to another user,
                   a rule without a run-as list is outside this criterion); it
                   carries the command ALL, not negated, with NOPASSWD in
                   force; no command in it is negated; and its principals -
                   none negated, none an alias - include one that is not
                   exactly the user root. A SPEC whose principals are only the
                   user root is excluded. The result names each declaration
                   with its file and line.
    MANUAL_REVIEW  the evidence is sufficient, no SPEC is decisive, and some
                   SPEC is an unresolved candidate: it carries NOPASSWD on ALL
                   or on a command alias, runs as root or through a run-as
                   alias or negation, concerns a principal other than only
                   root, and an alias, a named or negated host, a negation, or
                   a runas_default set in a user, host, run-as or command scope
                   or to different values decides whether it grants every
                   command as root without authentication.
    PASS           the evidence is sufficient and no SPEC is decisive and none
                   is an unresolved candidate: no declaration grants every
                   command as root without authentication to a principal other
                   than root, and no passwordless rule that could do so is left
                   unresolved.
  Never produced: NOT_APPLICABLE
  the result is a function of the committed evidence alone; evaluating the same
  snapshot again yields the same result and the same evidence references.

Limitations - what a result does not establish
  - Declared policy only: sudo's last-match rule is not applied, so a FAIL
    states the declared grant, not sudo's decision for one user - a later rule
    may still require a password for that user.
  - A %group grant is reported for the group; its members are not resolved from
    the evidence.
  - NOPASSWD on a named list of commands is outside this criterion: it is not
    every command.
  - Defaults !authenticate, which removes the password for every rule in its
    scope, is ISE-PRIV-002.
  - Only the local sudo policy files are read; LDAP and SSSD sudo rules are
    not.
  - A host other than ALL is not matched against this host's name: such a rule
    is a MANUAL_REVIEW, never a FAIL.
  - When runas_default is never set, sudo's documented default, root, is taken;
    a sudo built with another compiled-in default is not detected (sudo -V
    shows it).

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
      SPEC marks a user specification
  - sections/sudo.json
      /evidence/records/<i>/source_path
      the file of the declaration
  - sections/sudo.json
      /evidence/records/<i>/source_line
      the line of the declaration
  - sections/sudo.json
      /evidence/records/<i>/principals
      who the rule is for
  - sections/sudo.json
      /evidence/records/<i>/host
      the host the rule applies on
  - sections/sudo.json
      /evidence/records/<i>/runas_users
      the users the rule runs commands as
  - sections/sudo.json
      /evidence/records/<i>/runas_groups
      the groups the rule runs commands as
  - sections/sudo.json
      /evidence/records/<i>/commands
      the commands with their negation and tags in force
  - sections/sudo.json
      /evidence/records/<i>/scope_type
      the scope of a Defaults setting of runas_default
  - sections/sudo.json
      /evidence/records/<i>/scope
      that scope as written
  - sections/sudo.json
      /evidence/records/<i>/options
      the runas_default value

Manual verification (read-only)
  Read-only, as root: `sudo -ll -U <user>` lists what a user may run and with
  which tags; `visudo -c` checks the files. Neither changes anything.

Remediation guidance (illustrative; ISEDRAF changes nothing)
  Guidance only; ISEDRAF changes nothing. A rule granting every command without
  a password is usually narrowed to the commands that need it, or given back
  its password prompt, after confirming which automation depends on it; edit
  with visudo so a syntax error cannot lock sudo.

Baseline state  belongs to an evidence store, not to a criterion:
                `isedraf evaluate` (or `sudo isedraf evaluate`) compares the
                latest run with the store's approved baseline
Delta           per run, in the Baseline comparison of the evaluation and of
                the report (since 0.4.0)
```
