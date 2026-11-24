<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
<!-- GENERATED FILE — DO NOT EDIT MANUALLY.
     Source: lib/isedraf/catalog/native_controls.json
     Regenerate: python3 scripts/docs/criteria_pages.py generate
     `make check` fails when this page and the registry disagree. -->

# ISE-SSH-004

**GENERATED FILE — DO NOT EDIT MANUALLY**

This page renders the registry record, exactly as `isedraf explain ISE-SSH-004` does. The record is the only description of the criterion.

```text
ISE-SSH-004  (version 1, EXPERIMENTAL)
Global SSH Host-Based Authentication Disabled
Introduced in ISEDRAF 0.6.0. Needs at least a Full Audit: sshd -T is run only
  by a Full Audit (resolve_sshd_effective_config_v1); that is necessary, not
  sufficient.

Purpose
  Global SSH Host-Based Authentication Disabled: the global value of
  HostbasedAuthentication that sshd -T reports, as committed. The conclusion
  concerns the global configuration only.

Why it matters
  Host-based authentication lets a user log in because the connecting machine
  is trusted, without the user proving who they are. Anyone who controls a
  trusted machine, or can appear to be it, can then log in as the users it
  vouches for.

Check type      effective daemon configuration
Severity        high (default_severity; a FAIL finding takes it unchanged)
Applicability   Every Linux host where the Full Audit ran sshd -T.
                Role-independent. This criterion never yields NOT_APPLICABLE.

Facts required
  - the collection status of the resolved dimension: the coverage entry whose
    operation_id is resolve_sshd_effective_config_v1
  - the resolved setting hostbasedauthentication and its value

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
    - exactly one RESOLVED_SETTING record has keyword hostbasedauthentication
  Results:
    NOT_EVALUATED  the resolved dimension is not COLLECTED (every Standard
                   Audit, a refused or failed sshd -T), the setting is not
                   reported exactly once, or its value is neither yes nor no.
    PASS           the evidence is sufficient and the value is no: host-based
                   authentication is off globally.
    FAIL           the evidence is sufficient and the value is yes: the daemon
                   accepts host-based authentication, a login vouched for by
                   the connecting host.
  Never produced: NOT_APPLICABLE, MANUAL_REVIEW
  the result is a function of the committed evidence alone; evaluating the same
  snapshot again yields the same result and the same evidence references.

Limitations - what a result does not establish
  - Global effective configuration only: values that a Match block sets for
    some users, groups or addresses are not resolved, and a per-connection
    value may differ.
  - Which hosts are trusted (shosts.equiv, hosts.equiv, users' .rhosts and
    .shosts) is not read; ISE-SSH-005 concerns the users' files.

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
  Read-only, as root: `sshd -T | grep -i '^hostbasedauthentication'` prints the
  global value. The command changes nothing.

Remediation guidance (illustrative; ISEDRAF changes nothing)
  Guidance only; ISEDRAF changes nothing. HostbasedAuthentication is usually
  set to no unless a documented cluster relies on it; test with sshd -t before
  reloading.

Baseline state  belongs to an evidence store, not to a criterion:
                `isedraf evaluate` (or `sudo isedraf evaluate`) compares the
                latest run with the store's approved baseline
Delta           per run, in the Baseline comparison of the evaluation and of
                the report (since 0.4.0)
```
