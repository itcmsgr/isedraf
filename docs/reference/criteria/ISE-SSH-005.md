<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
<!-- GENERATED FILE — DO NOT EDIT MANUALLY.
     Source: lib/isedraf/catalog/native_controls.json
     Regenerate: python3 scripts/docs/criteria_pages.py generate
     `make check` fails when this page and the registry disagree. -->

# ISE-SSH-005

**GENERATED FILE — DO NOT EDIT MANUALLY**

This page renders the registry record, exactly as `isedraf explain ISE-SSH-005` does. The record is the only description of the criterion.

```text
ISE-SSH-005  (version 1, EXPERIMENTAL)
User Trust Files Ignored by SSH Host-Based Authentication
Introduced in ISEDRAF 0.6.0. Needs at least a Full Audit: sshd -T is run only
  by a Full Audit (resolve_sshd_effective_config_v1); that is necessary, not
  sufficient.

Purpose
  User Trust Files Ignored by SSH Host-Based Authentication: when host-based
  authentication is on globally, whether the global IgnoreRhosts that sshd -T
  reports, as committed, keeps users' own .rhosts and .shosts files from
  granting it. The conclusion concerns the global configuration only.

Why it matters
  Users' .rhosts and .shosts files let each user decide which remote machines
  may log in as them. With host-based authentication on, honouring those files
  hands a security decision to every account, where one careless file opens
  that account to another machine.

Check type      effective daemon configuration
Severity        medium (default_severity; a FAIL finding takes it unchanged)
Applicability   Hosts where the Full Audit ran sshd -T and
                HostbasedAuthentication is yes globally. NOT_APPLICABLE when it
                is no.

Facts required
  - the collection status of the resolved dimension: the coverage entry whose
    operation_id is resolve_sshd_effective_config_v1
  - the resolved settings hostbasedauthentication and ignorerhosts and their
    values

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
    - exactly one RESOLVED_SETTING record has keyword hostbasedauthentication,
      and exactly one has keyword ignorerhosts
  Results:
    NOT_EVALUATED  the resolved dimension is not COLLECTED (every Standard
                   Audit, a refused or failed sshd -T), a setting is not
                   reported exactly once, or a value is not one this criterion
                   knows.
    NOT_APPLICABLE the evidence is sufficient and HostbasedAuthentication is
                   no: host-based authentication is off globally, so no user
                   trust file can grant it (the documented condition of this
                   criterion; ISE-SSH-004 reports the method itself).
    PASS           the evidence is sufficient, HostbasedAuthentication is yes
                   and IgnoreRhosts is yes: users' .rhosts and .shosts files
                   are not used.
    FAIL           the evidence is sufficient, HostbasedAuthentication is yes
                   and IgnoreRhosts is no (users' .rhosts and .shosts files are
                   used) or shosts-only (users' .shosts files are used). The
                   result names the files that are allowed.
  Never produced: MANUAL_REVIEW
  the result is a function of the committed evidence alone; evaluating the same
  snapshot again yields the same result and the same evidence references.

Limitations - what a result does not establish
  - Global effective configuration only: values that a Match block sets for
    some users, groups or addresses are not resolved, and a per-connection
    value may differ.
  - The system-wide files /etc/hosts.equiv and /etc/ssh/shosts.equiv are
    outside this criterion: IgnoreRhosts does not govern them.
  - Whether any user actually has a .rhosts or .shosts file is not read.

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
  Read-only, as root:
  `sshd -T | grep -iE '^(hostbasedauthentication|ignorerhosts)'` prints both
  global values. The command changes nothing.

Remediation guidance (illustrative; ISEDRAF changes nothing)
  Guidance only; ISEDRAF changes nothing. Where host-based authentication is
  needed, IgnoreRhosts is usually set to yes so that only the system-wide trust
  files apply; test with sshd -t before reloading.

Baseline state  belongs to an evidence store, not to a criterion:
                `isedraf evaluate` (or `sudo isedraf evaluate`) compares the
                latest run with the store's approved baseline
Delta           per run, in the Baseline comparison of the evaluation and of
                the report (since 0.4.0)
```
