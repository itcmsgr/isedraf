<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Evidence model

This page explains what ISEDRAF records, what each status means, and why a run can be
trusted as a record of what was collected. It describes ISEDRAF 0.2.

## Collecting is not judging

ISEDRAF records what it saw and whether it could see it. It never decides whether what it
saw is good or bad. There is no PASS, FAIL, score or finding in 0.2.

A fact that could not be observed is reported as not observed, never as absent and never
as fine. That rule decides almost everything else on this page.

## One run, committed once

`isedraf audit` collects every area once and commits the result as one **run**. A run is a
directory under `snapshots/` in your evidence store:

```text
snapshots/SDS-<time>-<random>/
  manifest.json            what the run contains, with a digest of every file
  state/host_identity.json the pseudonymous host id
  method/host_identity.json how the host id was derived
  sections/<area>.json     one file per collected area, ten in all
```

The commit happens in a fixed order, under a lock that allows one run at a time:

```text
private temporary directory → collect → write files → digests → manifest → sync to disk
        → rename into snapshots/ → append one record to the ledger → sync
```

The ledger append is the moment a run becomes evidence. A directory in `snapshots/` that
the ledger does not record is an interrupted run: it is not evidence, and it is never
reported as a run. ISEDRAF does not rewrite a committed run.

## The four statuses

Every area, and the run as a whole, carries one collection status.

| Status | Meaning | What you may conclude |
|---|---|---|
| COLLECTED | every source for the area was read completely | the recorded facts describe what those sources said |
| PARTIAL | some sources were read, some were not | only what was read; the reason names what is missing |
| NOT_TESTED | the area could not be observed at all | nothing about that area, in either direction |
| ERROR | observation was attempted and failed | nothing; the run continued with the other areas |

The run is COLLECTED only when every area is. If any area is ERROR the run is ERROR;
otherwise it is PARTIAL. Each non-COLLECTED area carries a reason, such as
`SOURCE_UNREADABLE: etc/shadow could not be read: permission denied`.

A missing tool is NOT_TESTED; a tool that was present and failed is ERROR. Neither is ever
shown as an empty success.

## Run mode and privilege level

Every run records its run mode, and the report states it:

| Run mode | Command | Report line |
|---|---|---|
| STANDARD_AUDIT | `isedraf audit`, as your own user | PRIVILEGE LEVEL: UNPRIVILEGED |
| FULL_AUDIT | `sudo isedraf audit` | PRIVILEGE LEVEL: FULL_AUDIT |

In a standard audit, sources only root can read, such as `/etc/shadow` and the sudo policy,
are NOT_TESTED or PARTIAL with a reason. NOT_TESTED means those facts were not observed. It
does not mean they passed, and it does not mean they are absent. Runs committed by 0.1.x
carry no run mode; their reports show none rather than a guessed one.

## How each source was acquired

Each source a run tried to read is recorded with how it was read. `CURRENT_IDENTITY` means
the collecting identity read it itself: your own user, or in Full Audit the unprivileged
`isedraf` account. `SUPERVISOR_FIXED_OPERATION` means it was read by one of Full Audit's four
fixed privileged operations, which the record names. A section can mix both and still be
COLLECTED. A Full Audit report summarizes this per operation from the run's record.

## A file is not the whole system

Reading a file correctly is not the same as knowing what the system does with it.
ISEDRAF can read `/etc/passwd` completely; whether the system actually looks accounts up in
that file depends on the name service configuration (`/etc/nsswitch.conf`).

The two are recorded as separate facts. The report shows the file's record count, and on a
separate line "/etc/passwd consulted by NSS":

| Value | Meaning |
|---|---|
| ACTIVE | the configuration lists local files as a source |
| INACTIVE | only other known sources are configured, such as a directory service |
| NOT_ASSERTED | the configuration could not be interpreted reliably, so no claim is made |

The same pattern appears elsewhere: the declared hostname and the one the kernel is using
are recorded separately, with their relation (EQUAL, DIFFERENT or NOT_COMPARABLE).

## A tool change is not a host change

Each run records the ISEDRAF version and how each fact was collected, separately from the
facts themselves. A new ISEDRAF version, or a different collection method, on an unchanged
host must never look like the host changed. ISEDRAF does not yet compare runs, but it
keeps this separation so a later comparison can respect it.

## How a run is verified

Three kinds of digest tie a run together:

- each file in the run has a digest, listed in `manifest.json`;
- the manifest itself has a digest;
- each ledger record names the manifest digest and the digest of the record before it,
  forming a chain.

ISEDRAF checks all three right after committing a run, and again every time it renders a
report. The report states the result ("verified: hashes, bindings and ledger chain hold").
Every digest is SHA-256, and anyone can recompute them without ISEDRAF; the
[Auditor guide](AUDITOR_GUIDE.md) shows how.

`sudo isedraf report` re-verifies the ledger chain and the run it reports, from the bytes
it was given, before it renders anything, and the report states that scope; other runs in
the store are not re-verified by it.

Verification shows that the files have not changed since they were committed, as far as
the ledger can tell. It cannot show that the host told the truth, or that someone with
root did not replace the whole store.

## Host identity

Each run carries a **host id**: a SHA-256 digest derived from the host's machine-id. It is
pseudonymous, not anonymous: the same host gives the same id, and anyone holding the
machine-id can recompute it. The raw machine-id is never stored in the run or shown in a
report. Hosts cloned without regenerating their machine-id share a host id.

## Where the evidence lives, and who can read it

A standard audit's store is `~/.local/state/isedraf` (or `$XDG_STATE_HOME/isedraf`), a
directory owned by you with mode 0700; files are created mode 0600. A Full Audit's store is
`/var/lib/isedraf`, owned by root with mode 0700. Both are protected by filesystem
permissions only. Each run and ledger record states its evidence class:

| Class | Produced by |
|---|---|
| USER_PRODUCTION | a standard audit as your own user |
| SYSTEM_PRODUCTION | a Full Audit |
| DEV | a run with `ISEDRAF_STATE_ROOT` set; for development, never production evidence |

## Normative references

For readers who need the binding text: collection versus evaluation and status semantics
(EVID-001, SCOPE-045, D-13); commit order and orphaned runs (SNAP-014, SNAP-018, D-50);
section binding (D-115); user store and storage checks (STORE-026, STORE-027, D-116);
run modes and acquisition authority (AUTH-009, AUTH-017); the Full Audit store and report
(AUTH-022, AUTH-032); development runs (PRIV-004). The frozen design is under
[docs/architecture](architecture/).
