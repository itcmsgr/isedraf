<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Storage and Outputs — where ISEDRAF puts what

Status: EXPERIMENTAL · Canonical operator reference for storage locations.

> **Logs explain the run. Evidence describes the host.**

If you remember one sentence from this page, remember that one. It decides what you back up, what you
may rotate away, and where you look when something is wrong.

## The four roots

| Root | Holds | Lifecycle |
|---|---|---|
| `/etc/isedraf/` | administrator configuration | you own it; ISEDRAF reads it |
| `/var/lib/isedraf/` | **persistent canonical state and evidence** | ISEDRAF owns it; back this up |
| journal (`journalctl -t isedraf`) | operational/execution records | rotated by journald policy |
| `/run/isedraf/` | ephemeral runtime state | gone at reboot |

Two of those four are **not** where a reader coming from other tools expects them. That is deliberate and
is explained in [Operational logs](#operational-logs) below.

## Current implementation status

W1-B implements the first vertical slice — `isedraf identity` — and nothing beyond it. Read this table
before assuming a directory exists on your system.

| Path | Status | Notes |
|---|---|---|
| `/var/lib/isedraf/` | **IMPLEMENTED** | created mode `0700` |
| `/var/lib/isedraf/snapshots/` | **IMPLEMENTED** | one directory per committed snapshot |
| `/var/lib/isedraf/ledger/segment-000001.jsonl` | **IMPLEMENTED** | hash-chained records |
| `/var/lib/isedraf/tmp/` | **IMPLEMENTED** | staging for the atomic commit; not evidence |
| `/var/lib/isedraf/.lock` | **IMPLEMENTED** | whole-run exclusive lock |
| `/var/lib/isedraf/host/` | PLANNED | `host.json`, anchor key — not collected in W1 |
| `/var/lib/isedraf/baselines/` | PLANNED | W1-B freeze set; approval is not implemented |
| `/var/lib/isedraf/evaluations/` | PLANNED | requires comparison, which is W1-C |
| `/var/lib/isedraf/acceptances/` | PLANNED | requires baseline approval |
| `/var/lib/isedraf/reports/` | **IMPLEMENTED** under the development state root | `isedraf report --save` writes `reports/<YYYY>/<MM>/RPT-*.md` or `.json`, mode `0600` |
| `/var/lib/isedraf/exports/` | PLANNED | no export path exists |
| `/etc/isedraf/` | PLANNED | ISEDRAF reads no configuration file yet |
| `/run/isedraf/` | PLANNED | see the note on runtime state |
| journal records | PLANNED | `EXEC-005`; the CLI currently writes to stdout/stderr only |

Everything marked PLANNED is described here so the intended shape is knowable, **not** because it exists
today. `isedraf identity` currently creates exactly four things under the state root: `snapshots/`,
`ledger/`, `tmp/` and `.lock`.

## Persistent evidence — `/var/lib/isedraf/`

This is the evidence store. Its layout is fixed by a frozen requirement (`STORE-001`), and W1-A's
certified subset is fixed by `STORE-025`.

```text
/var/lib/isedraf/                     mode 0700
├── snapshots/                        IMPLEMENTED — immutable observed state
│   └── SDS-20260918T142500Z-<16 hex>/
│       ├── manifest.json             canonical bytes + manifest_hash
│       ├── state/host_identity.json  the hashed state object
│       └── method/host_identity.json how it was collected (provenance)
├── ledger/                           IMPLEMENTED
│   └── segment-000001.jsonl          hash-chained evidence lifecycle records
├── tmp/                              IMPLEMENTED — staging only
├── .lock                             IMPLEMENTED — whole-run exclusive lock
├── host/                             PLANNED
├── baselines/                        PLANNED
├── evaluations/                      PLANNED
├── acceptances/                      PLANNED
├── reports/                          PLANNED
└── exports/                          PLANNED
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

`ledger/segment-000001.jsonl` — one JSON object per line, hash-chained: each record carries the previous
record's hash, and `sequence` increments with no gaps.

It is **not** a diagnostic log:

- it is append-only in normal operation;
- it carries identifiers and hashes, never a copy of host state and never personal data;
- a verified record is never rewritten;
- **it must not be managed by logrotate**;
- editing it by hand breaks the chain, which is exactly what the chain exists to reveal.

The filename is `segment-NNNNNN.jsonl`, plural-segment form, never a single `ledger` file. Segments roll
on recovery.

### Baselines, evaluations, acceptances — PLANNED

`baselines/` will hold approved reference state. **An approved baseline means "this is the state we
accepted", not "this host is secure" and not "this host is compliant."** ISEDRAF records what it observed
and what you approved; it does not certify a host.

`evaluations/` will hold **derived, regenerable** interpretations of a snapshot against a baseline.
Re-running an evaluation with a newer rule set produces a new evaluation — it never rewrites the snapshot
it interpreted. That separation is the reason a rule change can never look like a host change.

### Reports and exports — PLANNED

| | |
|---|---|
| **report** | evidence-derived output for you or an auditor to read, kept under `/var/lib/isedraf/reports/` |
| **export** | an artifact deliberately prepared to be carried elsewhere, under `/var/lib/isedraf/exports/` |

Reports belong in the evidence root rather than alongside operational logs, for one practical reason:
log retention may legitimately delete old logs, and evidence you may need to produce later must not
disappear with them.

ISEDRAF has no network egress. An export is a file you move; nothing uploads it.

## Operational logs

**There is no `/var/log/isedraf/`, and there is not intended to be one.**

A frozen requirement (`SCOPE-062`) limits ISEDRAF to writing inside `/var/lib/isedraf`, with two named
exceptions: journald-mediated log records, and systemd transient-unit runtime state. Run start and end go
to the **journal** with a run ID (`EXEC-005`), not to a private log tree.

```bash
journalctl -t isedraf                  # PLANNED: once journal logging is implemented
journalctl -t isedraf --since today
```

Today, `isedraf identity` writes its operator output to stdout and its errors to stderr, and nothing else.
Per-run diagnostic directories are **not implemented** and would require an amendment to `SCOPE-062`
before they could be.

What operational records are for: execution progress, collector and parser errors, timing, warnings,
troubleshooting. What they are **not**: canonical snapshots, approved baselines, ledger authority, or any
evidence relied upon for comparison. If you keep only the logs, you have kept none of the evidence.

## Runtime state — `/run/isedraf/` (PLANNED)

Ephemeral coordination only, and it disappears at reboot. Today the whole-run lock lives at
`/var/lib/isedraf/.lock`, which is where `STORE-001` puts it. `/run/isedraf/` is listed here because it is
the natural home for future runtime state, not because anything uses it.

Nothing that must survive a reboot may live only in a runtime directory.

## Configuration — `/etc/isedraf/` (PLANNED)

Administrator intent belongs in `/etc/isedraf/`; ISEDRAF's own state belongs in `/var/lib/isedraf/`. The
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

| I want to see… | Location | Status |
|---|---|---|
| Everything ISEDRAF persists | `/var/lib/isedraf/` | IMPLEMENTED |
| Immutable observed state | `/var/lib/isedraf/snapshots/` | IMPLEMENTED |
| The evidence lifecycle chain | `/var/lib/isedraf/ledger/segment-*.jsonl` | IMPLEMENTED |
| Approved baseline | `/var/lib/isedraf/baselines/` | PLANNED |
| Derived evaluations and deltas | `/var/lib/isedraf/evaluations/` | PLANNED |
| Human/machine reports | `/var/lib/isedraf/reports/` | PLANNED |
| Portable exports | `/var/lib/isedraf/exports/` | PLANNED |
| Why a run failed | `journalctl -t isedraf`, plus the command's own stderr | PLANNED / IMPLEMENTED |
| Locks and temporary state | `/var/lib/isedraf/.lock`, `/var/lib/isedraf/tmp/` | IMPLEMENTED |
| Administrator configuration | `/etc/isedraf/` | PLANNED |

## Backup

Back up **`/var/lib/isedraf/`**. That is the evidence.

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
isedraf identity          # IMPLEMENTED — collect host identity, commit a snapshot
isedraf inventory         # IMPLEMENTED — host inventory; --json for the object
                          #   not written into a snapshot yet: SNAP-021 freezes a
                          #   W1-A snapshot as exactly three files
isedraf --version         # IMPLEMENTED
isedraf report            # IMPLEMENTED — system assurance report; --json,
                          #   --profile <file>, --save
isedraf verify            # PLANNED
isedraf explain <id>      # PLANNED
isedraf snapshot          # PLANNED
isedraf delta             # PLANNED
isedraf export            # PLANNED
```

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
