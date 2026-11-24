<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Storage and Outputs — where ISEDRAF puts what

Status: EXPERIMENTAL · Canonical operator reference for storage locations.

> **Logs explain the run. Evidence describes the host.**

If you remember one sentence from this page, remember that one. It decides what you back up, what you
may rotate away, and where you look when something is wrong.

## The evidence stores

ISEDRAF keeps its evidence in one store per route. Which store a command uses depends only on how it
is run:

| Store | Path | Used by | Evidence class |
|---|---|---|---|
| user store | `$XDG_STATE_HOME/isedraf/` when that is an absolute path, otherwise `~/.local/state/isedraf/` | `isedraf audit`, `isedraf evaluate`, `isedraf report`, `isedraf list`, as your normal user (Standard Audit) | `USER_PRODUCTION` |
| system store | `/var/lib/isedraf/` | `sudo isedraf audit`, `sudo isedraf evaluate`, `sudo isedraf baseline approve`, `sudo isedraf report`, `sudo isedraf list` (Full Audit) | `SYSTEM_PRODUCTION` |
| development store | the path in `ISEDRAF_STATE_ROOT` | testing only (see below) | `DEV`, never production evidence |

The user store is created mode `0700` and owned by you. It is refused - nothing is written - when it is
a symlink, owned by someone else, not mode `0700`, or on a network or unknown filesystem (NFS,
CIFS/SMB, FUSE and similar). The system store is owned by `root`, mode `0700`; the package creates it
when it is missing. A Full Audit's collectors run under the reduced `isedraf` account; the store
itself is written by the root side of the route.

An approved baseline exists only in the system store (and in a development store); a user store never
holds one. Uninstalling the package never removes either store: **back them up like any other data
you keep.**

`/etc/isedraf/`, the journal and `/run/isedraf/` are not used (see below).

## What a store holds

| Path (under the store) | Written by | Notes |
|---|---|---|
| `snapshots/<SDS-id>/` | `audit` | one directory per committed run; never rewritten |
| `snapshots/<SDS-id>/sections/` | `audit` | one file per audited area, bound by the run's manifest |
| `snapshots/<SDS-id>/coverage/evidence_limits.json` | `audit` | what the run could and could not observe, bound by the manifest |
| `evaluations/<EVL-id>/` | `evaluate` | the criteria results, findings and baseline comparison of one run; derived and regenerable |
| `baselines/BL-000001.json`, `baselines/current` | `sudo isedraf baseline approve` | the approved baseline and the pointer to it (system or development store only) |
| `ledger/segment-NNNNNN.jsonl` | `audit`, `baseline approve` | hash-chained records; a run is committed when it is recorded here |
| `reports/<YYYY>/<MM>/RPT-*` | `isedraf report --save` | `.md`, `.json` or `.html`, mode `0600`; the user route only - `sudo isedraf report` writes to standard output and never saves |
| `tmp/` | every writing command | staging for the atomic commit; not evidence |
| `.lock` | every writing command | one run at a time |
| `host/`, `acceptances/`, `exports/` | - | PLANNED; not created |

## The store layout

The layout is fixed by a frozen requirement (`STORE-001`).

```text
<store>/                              mode 0700
├── snapshots/                        immutable observed state
│   └── SDS-20260918T142500Z-<16 hex>/
│       ├── manifest.json             canonical bytes + manifest_hash
│       ├── state/host_identity.json  the hashed state object
│       ├── method/host_identity.json how it was collected (provenance)
│       ├── sections/<area>.json      one audited area each
│       └── coverage/evidence_limits.json
├── evaluations/
│   └── EVL-20260918T142500Z-<16 hex>/
│       ├── manifest.json             what was evaluated, by which engine and catalogue
│       ├── results.json              one result per native criterion
│       ├── findings.json             a finding per FAIL (with severity) and per MANUAL_REVIEW
│       └── changes.json              the comparison with the approved baseline
├── baselines/                        system or development store only
│   ├── BL-000001.json                the approved reference state
│   └── current                       which revision is in force
├── ledger/
│   └── segment-000001.jsonl          hash-chained evidence lifecycle records
├── reports/                          saved renderings (isedraf report --save)
├── tmp/                              staging only
└── .lock                             one run at a time
```

### Snapshots

A snapshot is **observed host state at a moment**. It is not a report, not a finding, not a verdict, and
not automatically a baseline. Snapshots are treated as immutable by ISEDRAF and are never rewritten by it.

`state/host_identity.json` is **absent** when collection did not succeed — and that absence is meaningful,
not an error: a snapshot recording what could *not* be collected is still evidence, and it is still
committed. The manifest says which case applies.

Do not edit anything inside a snapshot directory. Every byte is inside a hash preimage; editing one does
not "fix" a snapshot, it invalidates it — and the ledger will say so.

### The ledger

`ledger/segment-NNNNNN.jsonl` — one JSON object per line, hash-chained across segments: each record
carries the previous record's hash, and `sequence` increments with no gaps. It records committed runs,
baseline approvals and ledger recoveries.

It is **not** a diagnostic log:

- it is append-only within a segment;
- it carries identifiers and hashes, never a copy of host state and never personal data;
- a verified record is never rewritten;
- **it must not be managed by logrotate**;
- editing it by hand breaks the chain, which is exactly what the chain exists to reveal.

When the last write was interrupted (a crash or a full disk), the next `audit` or `baseline approve`
keeps the damaged segment byte for byte and continues the ledger in a new segment, with a record that
names the damaged one. `report`, `list` and `evaluate` never recover: they refuse and say which command
does.

### Evaluations and baselines

`evaluations/` holds **derived, regenerable** interpretations of a snapshot: the native criteria results
and, when a baseline is in force, the comparison with it. An evaluation belongs to the engine and the
criteria catalogue that made it; after an upgrade, `isedraf evaluate` makes a new one and never rewrites
the old. That separation is the reason a rule change can never look like a host change.

`baselines/` holds the approved reference state. **An approved baseline means "this is the state we
accepted", not "this host is secure" and not "this host is compliant."** ISEDRAF records what it
observed and what you approved; it does not certify a host. Only a complete Full Audit run can be
approved (`sudo isedraf baseline approve`).

### Reports and exports

| | |
|---|---|
| **report** | evidence-derived output for you or an auditor to read; `isedraf report --save` keeps it under `<store>/reports/` |
| **export** | an artifact deliberately prepared to be carried elsewhere, under `<store>/exports/` (PLANNED) |

Reports belong in the evidence root rather than alongside operational logs, for one practical reason:
log retention may legitimately delete old logs, and evidence you may need to produce later must not
disappear with them.

ISEDRAF has no network egress. An export is a file you move; nothing uploads it.

## Operational logs

**There is no `/var/log/isedraf/`, and there is not intended to be one.**

A frozen requirement (`SCOPE-062`) limits ISEDRAF to writing inside its evidence store, with two named
exceptions: journald-mediated log records, and systemd transient-unit runtime state. Run start and end go
to the **journal** with a run ID (`EXEC-005`), not to a private log tree.

```bash
journalctl -t isedraf                  # PLANNED: once journal logging is implemented
journalctl -t isedraf --since today
```

Every command writes its operator output to stdout and its errors to stderr; ISEDRAF writes no journal
records of its own yet. The Full Audit route (`sudo isedraf ...`) runs the engine in a systemd transient
unit (`systemd-run`), the second named exception, and relays its output and exit code. Per-run
diagnostic directories are **not implemented** and would require an amendment to `SCOPE-062`
before they could be.

What operational records are for: execution progress, collector and parser errors, timing, warnings,
troubleshooting. What they are **not**: canonical snapshots, approved baselines, ledger authority, or any
evidence relied upon for comparison. If you keep only the logs, you have kept none of the evidence.

## Runtime state — `/run/isedraf/` (PLANNED)

Ephemeral coordination only, and it disappears at reboot. The whole-run lock lives at
`<store>/.lock`, which is where `STORE-001` puts it. `/run/isedraf/` is listed here because it is
the natural home for future runtime state, not because anything uses it.

Nothing that must survive a reboot may live only in a runtime directory.

## Configuration — `/etc/isedraf/` (PLANNED)

Administrator intent belongs in `/etc/isedraf/`; ISEDRAF's own state belongs in its evidence store. The
two are never mixed, so restoring configuration never overwrites evidence and restoring evidence never
changes your intent. No configuration file is read yet.

## Identifiers and timestamps

```text
SDS-20260918T142500Z-3f9a1c0b7d2e4a68     snapshot
RUN-20260918T142500Z-a1b2c3d4e5f60718     run
EVT-20260918T142500Z-99aa88bb77cc66dd     ledger event
```

UTC, always, with a literal `Z` and no fractional seconds. The 16 hex characters come from a cryptographic
random source.

**The timestamp is for navigation; it is not identity.** Two runs in the same second are distinguished by
the suffix, and integrity comes from the hashes, never from the clock. A host with a wrong clock produces
artifacts with wrong-looking names and fully valid hashes.

## Where do I look?

In this table `<store>` is your user store (`~/.local/state/isedraf/`, or `$XDG_STATE_HOME/isedraf/`)
for a Standard Audit, and `/var/lib/isedraf/` for a Full Audit. `isedraf list` and `sudo isedraf list`
show what each holds without reading the files yourself.

| I want to see… | Location | Status |
|---|---|---|
| Everything ISEDRAF persists | `<store>/` | IMPLEMENTED |
| Immutable observed state | `<store>/snapshots/` | IMPLEMENTED |
| One audited area of a run | `<store>/snapshots/<id>/sections/<area>.json` | IMPLEMENTED |
| What a run could not observe | `<store>/snapshots/<id>/coverage/evidence_limits.json` | IMPLEMENTED |
| Criteria results and the baseline comparison | `<store>/evaluations/<id>/` | IMPLEMENTED |
| Approved baseline | `/var/lib/isedraf/baselines/` | IMPLEMENTED (system store) |
| The evidence lifecycle chain | `<store>/ledger/segment-*.jsonl` | IMPLEMENTED |
| Saved reports | `<store>/reports/` (user store) | IMPLEMENTED |
| Portable exports | `<store>/exports/` | PLANNED |
| Why a run failed | the command's own stderr and its exit code (the journal is PLANNED) | IMPLEMENTED |
| Locks and temporary state | `<store>/.lock`, `<store>/tmp/` | IMPLEMENTED |
| Administrator configuration | `/etc/isedraf/` | PLANNED |

## Backup

Back up **the stores you use**: your user store, and `/var/lib/isedraf/` on a host where Full Audits
run. That is the evidence, the evaluations and the baseline.

Add `/etc/isedraf/` once configuration exists. Journal retention is a separate concern, useful for
troubleshooting and not a substitute for evidence.

Copying the files preserves what ISEDRAF recorded and lets the hashes be recomputed. It does **not** turn
those files into externally attested evidence: ISEDRAF's integrity claims are local, and they are not a
defence against a local root adversary who alters the store and the ledger together.

## Permissions

Directories `0700`, files `0600`, `umask 077`. The store may contain host-security evidence, so it is
readable only by the account that owns it.

Do not casually widen these to make a script's life easier. If something needs to read evidence, give it
a deliberate path in, not a world-readable store.

## Development state root

`ISEDRAF_STATE_ROOT` redirects the store for development and testing. It is **not** a supported way to
relocate production storage.

- honoured only when the effective UID is not 0 **and** `SUDO_USER` is unset;
- refused under root or through sudo;
- every artifact produced carries `"state_root": "DEV"` and can never be mistaken for production evidence.

```bash
ISEDRAF_STATE_ROOT=/tmp/isedraf-lab isedraf identity
```

## Use the CLI, not the filesystem

```bash
isedraf audit                    # every area once, one committed run (Standard Audit)
sudo isedraf audit               # the same as a Full Audit, into /var/lib/isedraf
isedraf evaluate                 # native criteria results and the baseline comparison
isedraf explain <criterion>      # what a criterion checks and does not establish
sudo isedraf baseline approve    # approve the latest complete Full Audit run
isedraf list                     # what the store holds; nothing written
isedraf report                   # report of the latest committed run;
                                 #   --html, --json, --profile <file>, --save
isedraf identity                 # developer: host identity only, one committed run
isedraf inventory                # developer: show the host inventory; commits nothing
isedraf help --all               # every command; `isedraf help <command>` for one
```

`verify`, `snapshot`, `delta` and `export` commands are PLANNED. Every command, its privileges, what it
writes and its exit codes: [CLI reference](../reference/CLI.md).

Direct filesystem access is legitimate for inspection, backup, forensics and integration with tooling you
control. It is not a way to change what ISEDRAF recorded: manual modification does not update the
manifest or the ledger, so it converts evidence into something that fails its own verification.

## Which fact lives in which artifact

This page says *where* things are stored. For *what* a stored fact means — its Linux source, the
normalized field that represents it, and the conclusions it does not support — see the
[Control & Evidence Map](../reference/CONTROL_EVIDENCE_MAP.md).

## Terminology

| Term | Means |
|---|---|
| snapshot | observed host state at a moment, immutable |
| baseline | reference state you approved — **not** "secure state" |
| evaluation | derived interpretation of a snapshot against a baseline; regenerable |
| report | evidence-derived output for a person or an auditor |
| export | artifact deliberately prepared to leave the host |
| ledger | hash-chained record of evidence lifecycle events |
| operational log | what the program did while running |
| run | one invocation, identified by a `RUN-` id |
| runtime state | ephemeral coordination data such as a lock |

A report is not a log. A snapshot is not a report. A ledger is not a log. A baseline is not a security
verdict. These distinctions are what let evidence be reasoned about later.
