<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
<!-- GENERATED FILE — DO NOT EDIT MANUALLY.
     Source: lib/isedraf/catalog/native_controls.json
     Regenerate: python3 scripts/docs/criteria_pages.py generate
     `make check` fails when this page and the registry disagree. -->

# ISE-STORAGE-001

**GENERATED FILE — DO NOT EDIT MANUALLY**

This page renders the registry record, exactly as `isedraf explain ISE-STORAGE-001` does. The record is the only description of the criterion.

```text
ISE-STORAGE-001  (version 1, EXPERIMENTAL)
/dev/shm Mounted nosuid
Introduced in ISEDRAF 0.6.0. Needs at least a Full Audit: only a Full Audit
  reads the host's mount table (/proc/1/mountinfo); a Standard Audit reads its
  own process's view and cannot establish the host's namespace; that is
  necessary, not sufficient.

Purpose
  /dev/shm Mounted nosuid: whether the active mount at /dev/shm in the host's
  mount table, as committed, carries the nosuid option. The conclusion concerns
  that mount only.

Why it matters
  /dev/shm is writable by every user. Without nosuid, a set-user-ID program
  placed there runs with its owner's privileges, which turns a world-writable
  directory into a place to stage privilege escalation.

Check type      mount protection options
Severity        medium (default_severity; a FAIL finding takes it unchanged)
Applicability   Every Linux host whose Full Audit read the host's mount table.
                Role-independent. This criterion never yields NOT_APPLICABLE.

Facts required
  - whether the active mount table was collected completely, and that it was
    read from the host's mount table (/proc/1/mountinfo)
  - the active mount at /dev/shm: its mount point, file system type, parse
    status and per-mount options

Dimensions
  declared  not evaluated: /etc/fstab may not declare /dev/shm, and a declared
            option is not the one in effect
  resolved  not evaluated
  active    the mount in effect in the host's mount table (PID 1's mount
            namespace)

How it is evaluated
  Input: the committed, verified snapshot only: sections/mounts.json whose
    digest matches the snapshot manifest. Only a Full Audit reads the host's
    mount table.
  Evidence is sufficient when:
    - the active side of the mounts section is COLLECTED and complete
    - every active mount record was read from /proc/1/mountinfo (the host's
      mount namespace)
    - exactly one active mount has the mount point /dev/shm, and its line was
      parsed
  Results:
    NOT_EVALUATED  the evidence is not sufficient: an incomplete or uncollected
                   active table, a table that is not the host's (every Standard
                   Audit), no mount at /dev/shm, more than one mount at
                   /dev/shm, or an unparsed mount line.
    PASS           the evidence is sufficient and the /dev/shm mount carries
                   nosuid.
    FAIL           the evidence is sufficient and the /dev/shm mount does not
                   carry nosuid. The result shows the mount point and the
                   options observed.
  Never produced: NOT_APPLICABLE, MANUAL_REVIEW
  the result is a function of the committed evidence alone; evaluating the same
  snapshot again yields the same result and the same evidence references.

Limitations - what a result does not establish
  - The host's mount namespace only (PID 1's): containers and other mount
    namespaces are not observed.
  - Other options of /dev/shm (nodev, noexec) and other world-writable mounts
    (/tmp, /var/tmp) are outside this criterion.
  - The options in effect at collection time; a later remount is not seen.

Evidence pointers
  - manifest.json
      /manifest_core/auxiliary_artifacts/sections~1mounts.json
      the digest that binds the mounts section
  - sections/mounts.json
      /evidence/provenance/comparison/active_status
      the collection status of the active mount table
  - sections/mounts.json
      /evidence/provenance/active/universe_complete
      whether the active table was read completely
  - sections/mounts.json
      /evidence/provenance/active/records/<i>/mount_point
      the mount point
  - sections/mounts.json
      /evidence/provenance/active/records/<i>/source_path
      the mount table read (/proc/1/mountinfo is the host's)
  - sections/mounts.json
      /evidence/provenance/active/records/<i>/parse_status
      whether the mount line was parsed
  - sections/mounts.json
      /evidence/provenance/active/records/<i>/fstype
      the file system type
  - sections/mounts.json
      /evidence/provenance/active/records/<i>/mount_options
      the per-mount options in effect

Manual verification (read-only)
  Read-only: `findmnt -no OPTIONS /dev/shm` prints the options in effect. The
  command changes nothing.

Remediation guidance (illustrative; ISEDRAF changes nothing)
  Guidance only; ISEDRAF changes nothing. nosuid is usually added to the
  /dev/shm entry in /etc/fstab (or the systemd mount unit) and applied with a
  remount at a planned time, after checking that no software relies on
  set-user-ID programs there.

Baseline state  belongs to an evidence store, not to a criterion:
                `isedraf evaluate` (or `sudo isedraf evaluate`) compares the
                latest run with the store's approved baseline
Delta           per run, in the Baseline comparison of the evaluation and of
                the report (since 0.4.0)
```
