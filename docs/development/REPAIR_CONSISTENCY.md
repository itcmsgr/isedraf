<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Repair Consistency Process

Status: IMPLEMENTED
Implements: GOV-001, GOV-002, D-105, D-106

## Why this exists

Round 2 of the adversarial review found that **seven of its twenty-six findings were the same defect**:
a fix landed in one authoritative document and not the others. Two more blocking findings were
*repair-induced* — introduced by the previous round's repairs.

A repair is not complete when the sentence is changed. It is complete when the **concept** is consistent
everywhere it appears.

## Required before any architecture repair is declared complete

Produce a consistency matrix for every changed concept:

```text
CHANGED CONCEPT
  ├── affected decision IDs
  ├── affected requirement IDs
  ├── affected documents
  └── affected planned tests / gates
```

Then sweep **every** listed document, not only the one that motivated the change.

## Then run

| Check | Command |
|---|---|
| Requirement-reference validation | `make check-refs` |
| Decision-reference validation | `make check-refs` |
| Amendment-not-cited-as-authority | `make check-refs` |
| Canonical terminology and forbidden claims | `make check-docs` |
| Path and name consistency | `make check-docs`, `make check-headers` |
| Master-index regeneration | `make check-index` |
| Header grammar (one syntax, no governance keys in docstrings) | `make check-headers` |
| Falsifiability of every gate touched | `make check-falsifiable` |

`make check` runs all but the last.

## The documents a concept usually touches

`DECISIONS_REGISTER.md` · `ISEDRAF_HLD.md` · `EVIDENCE_AND_TRUST_MODEL.md` ·
`SNAPSHOT_BASELINE_DELTA_MODEL.md` · `V0_1_IMPLEMENTATION_SCOPE.md` · `OPEN_DECISIONS.md` ·
`MASTER_INDEX.md` · `CLAUDE.md` · `README.md` and the `/docs` governance set · the planned test and gate
inventory in `CI_INVENTORY.md`.

## Known propagation traps

| Trap | Caught by |
|---|---|
| Renumbering a requirement leaves stale references | `check-refs` — it caught a duplicate `PRIV-006` and two stale privilege references during the Round 3 repair itself |
| Adding a requirement changes index counts | `check-index` — it fired on `STORE-020` |
| A new requirement cites one defined later | `check-refs` — it caught a forward `IDENT-070` reference |
| A term is renamed in one document (`ORPHANED` → `ORPHANED_UNLEDGERED`) | manual sweep, then `check-docs` |
| A layout change lands in one place (singular ledger file → `ledger/`) | **`make check-paths`** — prose review missed four copies of this one path (T-07) |
| A file-wide lint exemption silently disables a gate | `check-docs` now rejects the exemption outside documents whose purpose is to enumerate forbidden terms |

## The principle

This is `GOV-001` applied to the repair process itself: an invariant that is neither enforced nor
documented as unenforceable is a defect. A repair that is not propagated is not a repair — it is a new
inconsistency with a good intention.
