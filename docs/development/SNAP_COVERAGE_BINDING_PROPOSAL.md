<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# SNAP amendment proposal — binding the Evidence Limits Manifest

Status: PLANNING
Implements: SCOPE-045, GOV-001

**OWNER ACTION REQUIRED. Nothing in this document is implemented.** It is the analysis
ruling A asked for, stated before implementation, and it stops here because the change it
needs is an amendment to a frozen contract and `AMENDMENTS.md` is owner-controlled.

## 1. The current binding chain, as measured

    ledger  record_core { sequence, previous_record_hash, snapshot_id, manifest_hash, ... }
              -> record_hash = H(DOMAIN_LEDGER_RECORD, canonical(record_core))
              -> chained by previous_record_hash                      STORE-024
                        ^
                        | binds
    snapshot  manifest_hash = H(DOMAIN_SNAPSHOT_MANIFEST, canonical(manifest_core))
                        ^
                        | binds
              manifest_core { schema_version, host_id, snapshot_id, run_id, created_at,
                              state_root, engine_version,
                              sections.host_identity.state_hash, ... }   SNAP-020
                        ^
                        | binds
              state/host_identity.json   via state_hash = H(DOMAIN_STATE, bytes)

`verify_snapshot` checks exactly three things: that `manifest.json` is canonical bytes of
its object, that `manifest_hash` matches its preimage, and that `state_hash` matches
`state/host_identity.json`.

## 2. The gap

    coverage/evidence_limits.json      NOT referenced by manifest_core
                                       NOT checked by verify_snapshot
                                       carries its own coverage_digest, self-describing

`coverage_digest` proves only *these bytes hash to this value*. It does not prove *this is
the coverage artifact that belonged to this snapshot*. Replace the file and its digest
together and nothing in the chain objects. R1.5-P makes that security-significant, because
the file now decides `absence_claim_allowed` and `privilege_limited`.

A one-directional binding does not close it. Putting `snapshot_id` and `manifest_hash`
inside the coverage object makes the coverage name its snapshot, but the snapshot still
does not name the coverage, so substituting a different validly-formed coverage object for
the same snapshot stays undetected.

### A pre-existing instance of the same gap

`method/host_identity.json` is written into every snapshot and is bound by nothing.
`manifest_core` carries method *metadata* — collector and parser versions — but no digest
of the file, and `verify_snapshot` never opens it. It can be replaced undetected today.

This is not caused by R1.5-P and is reported because it changes the right shape of the
amendment: the repository needs **a way to bind auxiliary bundle artifacts**, not a
one-off field for coverage.

## 3. Proposed amendment — the smallest form

Add one field to the SNAP-020 field table:

    manifest_core["auxiliary"] = {
        "<relative path>": "<digest of the file's bytes>",
        ...
    }

- Present always, `{}` when there is no auxiliary artifact, because NORM-034 makes absent
  and empty different statements.
- Keys are bundle-relative paths; values are `H(DOMAIN_AUXILIARY, bytes)` under a new
  canonical domain, keeping them un-confusable with a state hash (NORM-038).
- `verify_snapshot` gains: every listed path exists and matches; **and no unlisted file
  exists in the bundle**, so an artifact cannot be added silently either.
- `coverage/evidence_limits.json` and `method/host_identity.json` both become entries.

This binds coverage transitively through `manifest_hash` into the chained ledger record,
with no new mechanism and no second integrity concept.

### It does not merge the two identities

`coverage_digest` stays inside the coverage object and stays computed over coverage facts
alone. `auxiliary` binds the *bytes of the file*; it does not put coverage facts into the
state hash, and `state_hash` is untouched. So:

    host-state identity      state_hash            unchanged by any coverage change
    observation-capability   coverage_digest       changes when visibility changes
    bundle integrity         manifest_hash         changes when either file changes

A future R3 compares the first two and must not use the third: `manifest_hash` changing
means *something in the bundle changed*, which is not a host-state delta and never was —
`created_at` alone changes it on every run. That is worth stating in the amendment so the
distinction is recorded where R3 will look.

## 4. Compatibility effect

| Surface | Effect |
|---|---|
| `manifest_core` field table (SNAP-020) | **amended** — one key added |
| `manifest_hash` for any new snapshot | **changes** — expected consequence of the above |
| existing committed snapshots | none; nothing rewrites a committed snapshot |
| `state_hash`, `DOMAIN_STATE` | unchanged |
| ledger `record_core` (STORE-024) | unchanged — it binds `manifest_hash`, which still exists |
| `verify_snapshot` | gains two checks; existing checks unchanged |
| public API / CLI | none |

## 5. Golden-vector effect — measured

`test-vectors/w1a/v1/` holds **15 cases**. Each `expected/` contains
`manifest-core.canonical`, `manifest-hash.txt`, `manifest.json`, `record-core.canonical`,
`record-hash.txt`, `record.json`, plus state and method files.

Adding a key to `manifest_core` changes, per case: `manifest-core.canonical`,
`manifest-hash.txt`, `manifest.json` — and because `record_core` embeds `manifest_hash`,
also `record-core.canonical`, `record-hash.txt` and `record.json`. **Six files in each of
15 cases: 90 expected files regenerate.**

The vectors' purpose is preserved: they prove byte-identical canonical output across
CPython 3.6–3.14, and they will still do that after regeneration. What is lost is their
value as a *regression* record against the pre-amendment manifest shape, which is exactly
what an amendment to the shape means.

`NORM-039` requires the vectors to be regenerated and re-certified on both matrix lanes.

## 6. Why this stops here

`SNAP-020` is defined in `docs/architecture/SNAPSHOT_BASELINE_DELTA_MODEL.md` and
the W1-A freeze scope document, both hash-locked in the
`W1A_CORE` freeze set (D-107) and read-only to me. Amending a frozen requirement is an owner
act recorded in `AMENDMENTS.md`.

There is no binding that avoids it. Every anchor in the bundle is reached through
`manifest_core`, so binding anything new requires a field there — and a design that avoids
the amendment would either be one-directional (section 2) or would put coverage into the
state hash, which is the one thing the owner ruling forbids.

## 7. Exact text proposed for `AMENDMENTS.md`

> **SNAP-020 amendment — auxiliary bundle artifact binding.**
> `manifest_core` gains a required `auxiliary` object mapping each auxiliary bundle
> artifact's bundle-relative path to a digest of its bytes, computed under the canonical
> domain `ISEDRAF:AUXILIARY-ARTIFACT:V1`. The object is always present and is `{}` when
> the bundle holds no auxiliary artifact. `method/host_identity.json` and, when written,
> `coverage/evidence_limits.json` are auxiliary artifacts.
>
> Snapshot verification additionally requires that every listed path exists with matching
> bytes, and that the bundle contains no auxiliary artifact absent from the list.
>
> This binds auxiliary artifacts transitively through `manifest_hash` into the ledger
> chain. It does not alter `state_hash`, `DOMAIN_STATE`, or what constitutes host state:
> an auxiliary artifact is `PROVENANCE` under `SCOPE-045`, it is never hashed or diffed as
> host state, and a change to `manifest_hash` is not a host-state delta.
>
> Consequence: the `NORM-039` golden vectors are regenerated and re-certified on both
> supported interpreter lanes.

## 8. If the owner declines

R1.5-P freezes without the binding and the contract records, in the limitation the report
already renders, that the Evidence Limits Manifest travels with the bundle and is not
covered by its integrity chain. That is a weaker product and an honest one; what it must
not become is a claim of binding that the chain does not support.
