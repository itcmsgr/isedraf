# ISEDRAF Architecture — Master Index

Copyright © 2026 Antonios Voulvoulis / ITCMS · SPDX-License-Identifier: MPL-2.0
Status is defined externally: membership in `docs/architecture/FROZEN_MANIFEST.sha256` means FROZEN.
No manifest entry means candidate. Changing a status string would change the reviewed bytes, so it is not
`FROZEN_MANIFEST.sha256`

| Document | Status | Requirement ID ranges | Count |
|---|---|---|---|
| `ISEDRAF_HLD.md` | FROZEN CANDIDATE | `GOV-001`…`GOV-007` · `HLD-001`…`HLD-065` · `OUT-001`…`OUT-022` | 51 |
| `EVIDENCE_AND_TRUST_MODEL.md` | FROZEN CANDIDATE | `EVID-001`…`EVID-040` · `EXEC-001`…`EXEC-020` · `INTEG-001`…`INTEG-005` · `PRIV-001`…`PRIV-022` | 50 |
| `SNAPSHOT_BASELINE_DELTA_MODEL.md` | FROZEN CANDIDATE | `BASE-001`…`BASE-030` · `CMP-001`…`CMP-031` · `DELTA-001`…`DELTA-021` · `NORM-001`…`NORM-042` · `SNAP-001`…`SNAP-023` · `STORE-001`…`STORE-025` | 83 |
| `V0_1_IMPLEMENTATION_SCOPE.md` | FROZEN CANDIDATE | `EXPL-001`…`EXPL-002` · `IDENT-001`…`IDENT-070` · `REC-001`…`REC-010` · `SCOPE-001`…`SCOPE-077` | 54 |
| `HEADER_POLICY.md` | FROZEN CANDIDATE | `HDR-001`…`HDR-003` | 3 |
| **Total requirements** | | | **241** |

## Stubs — finalize after prototype

`HOST_STATE_MODEL.md` · `EXPORT_SCHEMA_AND_INTEGRATION_MODEL.md` · `IDENTITY_AND_PRIVILEGE_MODEL.md` ·
`REPORTING_MODEL.md` · `SOFTWARE_INVENTORY_FUTURE_MODEL.md` · `CI_AND_CORPUS_BLUEPRINT.md` ·
`PACKAGING_BLUEPRINT.md` · `COMPETITIVE_POSITIONING.md` · `PROVENANCE_POLICY.md` · `FILE_HEADER_POLICY.md`

## Requirement ID namespaces

| Prefix | Domain | Home document |
|---|---|---|
| `HLD` | product definition, boundary, architecture, journeys, CLI | HLD |
| `GOV` | enforceability, guardrails, amendments, AI disclosure | HLD §11 |
| `OUT` | exit codes, output surfaces, schema versioning | HLD §8–9 |
| `EVID` | trust boundaries, anti-deception, creation provenance, recording | Evidence & Trust |
| `PRIV` | privilege model, MAC, capabilities, dev state root | Evidence & Trust |
| `EXEC` | sandbox, execution hygiene, imports, syntax validation | Evidence & Trust |
| `INTEG` | tool integrity, trust levels, signing claims | Evidence & Trust |
| `NORM` | pipeline, dimensions, state/observation, canonical serialization | Snapshot/Baseline/Delta |
| `SNAP` | host applicability, snapshot lifecycle, commit ordering | Snapshot/Baseline/Delta |
| `BASE` | baseline revisions, acceptance, rebind | Snapshot/Baseline/Delta |
| `CMP` | collection vs evaluation, method versioning, comparability | Snapshot/Baseline/Delta |
| `DELTA` | change primitives, interpretation, guidance, quiet runs | Snapshot/Baseline/Delta |
| `STORE` | storage layout, ledger, acceptance records, retention | Snapshot/Baseline/Delta |
| `SCOPE` | tiers, platforms, domain pitfalls, milestones | v0.1 Scope |
| `IDENT` | identity domain semantics | v0.1 Scope |
| `REC` | recording coverage semantics | v0.1 Scope |
| `EXPL` | explain contract | v0.1 Scope |

Retired IDs are never reused (`HLD-063`).

## The five invariants and where they are enforced

**This table is authoritative** (finding R-14). `ISEDRAF_HLD.md` §5 names the invariants and points here.

| Invariant | Requirements | Acceptance tests |
|---|---|---|
| I-1 unchanged host stays quiet | `NORM-020`, `NORM-021`, `DELTA-010` | 2, 14 |
| I-2 incomplete evidence never creates a false delta | `CMP-001`, `CMP-002`, `CMP-030`, `CMP-031` | 5 |
| I-3 tool evolution never masquerades as host evolution | `CMP-020`, `CMP-021`, `BASE-030` | 3, 4 |
| I-4 snapshots treated as immutable by ISEDRAF, evaluations regenerable | `SNAP-010`…`SNAP-017` | 6 |
| I-5 host evidence boundary stays strict | `HLD-010`…`HLD-015`, `SCOPE-004` | 11, 12, 20 |
