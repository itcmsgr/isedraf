<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# W1-A Core Freeze Scope

Implements: D-68, D-105, D-107, NRM-001

## Why this exists, and why it is this small

Five review rounds on the full architecture produced blocking findings at 18 → 4 → 6 → 8, and the narrowed
W1 set produced 20 → 13. The ideas were not the problem; the **scope** was. W1 itself is split once more:

| Set | Content |
|---|---|
| **W1-A** *(this document)* | collect → normalize → canonicalize → snapshot → `snapshot_created` ledger |
| **W1-B** | DEV baseline approval, `BL-000001` |
| **W1-C** | comparison, evaluation, delta |

Per **D-107**, a verified freeze set authorizes implementation of **that set only**. There is no global
architecture manifest and none will be created.

## The principle that decides what is in here

**A durable evidence contract is frozen before code writes it. Everything else waits for the code.**

The snapshot manifest and the ledger record become bytes on disk that later versions must still read, so
they are specified now (`SNAP-020`, `STORE-024`). The evaluation manifest, the baseline revision object and
the evidence reference are **not** specified: W1-A writes none of them, and speculative bytes are worse
than absent ones. They will be informed by working code.

## What W1-A must prove

```text
unprivileged invocation → root refusal → DEV_STATE_ROOT validation → collect host_identity
  → classify → normalize → canonical bytes → SHA-256 → temp dir → fsync → atomic rename
  → snapshot_created ledger record → independent verification
```

| Invariant | Expected |
|---|---|
| same host, repeated run | byte-identical canonical STATE, identical section hash |
| golden fixture | exact expected canonical bytes, exact expected SHA-256 |
| snapshot after commit | not modified |
| ledger record | independently verifies |
| root execution | refused, exit `70` |
| valid unprivileged run | accepted, artifacts carry the DEV marker |

## FROZEN for W1-A

| Concept | Requirements |
|---|---|
| Canonical serialization and hashing | `NORM-030`…`NORM-039` (X-06: `NORM-030` carries the timestamp format and locale independence; `NORM-031` defines *section hash*) |
| Field classification | `SCOPE-045`, `SCOPE-046`, `SCOPE-047`, `NORM-020` |
| Host identity state, parser, status, derivation, source | `IDENT-002`…`IDENT-006` |
| Method identity | `CMP-020` (recording obligation only; `CMP-021` is comparison and moves to W1-C — Y-17) |
| Snapshot | `SNAP-010` (subtree/evidence clauses scoped out by `SNAP-021`), `SNAP-014`, `SNAP-018`, `SNAP-019`, `SNAP-020`, `SNAP-021`, `SNAP-022`, `HLD-032` |
| Storage layout | `STORE-001`, `STORE-025` (W1-A subset) |
| Ledger record and commit | `STORE-010` (enum), `STORE-024` (`STORE-023` is superseded for W1-A) |
| Execution mode | `SCOPE-070`, `SCOPE-071`, `SCOPE-072`, `PRIV-004` |
| Exit codes reachable in W1-A | `SCOPE-077` — `0`, `2`, `64`, `70` |
| Hostile input on W1-A surfaces | `OUT-013`, `OUT-015`, `EVID-002`, `EVID-004` |
| Governance | `GOV-001`…`GOV-003`, `GOV-006`, `D-105`, `D-106`, `D-107`, `NRM-001`…`NRM-003` |
| Header grammar | `HDR-001`…`HDR-003` |

## Explicitly NOT in W1-A

Baseline approval, `BL-000001`, the profile object and `profile_hash`, the DEV baseline class
(`BASE-009`), comparability, delta, evaluation manifests, evidence-reference objects, optional identity
anchors (DMI UUID, root-filesystem UUID, virtualization), confidence scores, HMAC anchor keys,
`POSSIBLE_CLONE`/`POSSIBLE_ROLLBACK`, and every concept already deferred to Freeze Set 2.

These remain design candidates in the architecture documents. They are **not** in the manifest, so they are
**not** frozen, and implementation SHALL NOT treat them as authority.

## Freeze mechanism

`freeze/W1A_CORE.sha256` freezes the **exact bytes** of every listed artifact — including
`docs/development/HEADER_POLICY.md`, which is outside `docs/architecture/` but carries `HDR-001`…`HDR-003`. This document identifies
which requirements **within** those artifacts are normative for W1-A. **Any later modification of a
manifested artifact invalidates this freeze and requires an explicit re-freeze.**

`check-freeze` is the sole authority on manifest validity and verifies: discovery, digest correctness,
tracked regular files only, no symlinks, no path traversal, no duplicate entries, no missing files, and
that a candidate tree with zero manifests **does not** claim frozen status. `check-scope` consumes that
verdict rather than testing for a filename (`D-107`, X-01).

## Release condition

```text
W1-A BLOCKING = 0   →   generate docs/architecture/freeze/W1A_CORE.sha256   →   implement W1-A
```

The running W1-A implementation then becomes the evidence that shapes W1-B.
