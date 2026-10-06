<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Post-GA Architecture Checkpoint

Status: PLANNING
Implements: D-111, D-112, D-117, D-118

This document compares the engine as built at GA 0.1.0 with the assurance model the releases after
it need. It records where each entity stands, the contract between v0.2 and v0.3, and how a
2026-10 design proposal fits the frozen decisions. It is planning material. It decides nothing:
the frozen documents and the decisions register remain the authority, and the conflicts below are
recorded in `docs/IMPLEMENTATION_QUESTIONS.md` for the owner (IQ-039 … IQ-043). IQ-039, IQ-040
and IQ-041 were resolved on 2026-10-06 by D-120 and D-121; §4 to §6 record the state before that.

The engineering repository was at `8f368da` when this was written. Labels follow
`docs/development/DOCUMENTATION_POLICY.md` §9.

## 1. Release sequence (owner decision, 2026-10-05)

```text
v0.1  Evidence Foundation     GA, published 2026-09-28; unprivileged; USER_PRODUCTION
v0.2  Evidence Authority      Full Audit (D-118): privileged collection authority, plus the
                              observation/evidence/capability contract that v0.3 consumes
v0.3  Assurance Semantics     native ISE-* controls, evaluation, results, findings
v0.4  Historical Assurance    approved baseline, classified run-to-run delta
v0.5  Framework Intelligence  mapping overlays, coverage, overlap, gaps; Modes A/B/C (D-112)
```

The owner chose this order over a proposal that put the control model in v0.2, and gave three
reasons:

- **Full Audit was already v0.2** (owner direction 2026-09-27, `docs/roadmap/ROADMAP.md`). Nothing
  is gained by reordering a recorded direction.
- **BASE-003 stays as it is.** An unprivileged or incomplete snapshot is never approvable (CLAUDE.md
  §3, D-117 §4, OD-16). Approving a snapshot that could not observe privileged state, and later
  reporting "no relevant change", would claim knowledge the collection never had. Baselines
  therefore follow privileged, authoritative snapshots, so v0.4 comes after v0.2.
- **Collection authority sits underneath the control model.** A control that needs root-only
  evidence would mostly evaluate to "not tested" on an unprivileged engine. v0.3 should get
  evidence that is already authoritative and should not care whether it came from Python, a
  compiled worker, root or an unprivileged process.

Preserved without change: the `ISE-*` namespace and its 14 families (D-111), Modes A/B/C (D-112),
BASE-003 and OD-16, and the D-118 execution model. The compiled acquisition core stays
measurement-gated and is not tied to a version.

## 2. Entity status

Each code status was checked against `lib/isedraf/` (REPOSITORY FACT). Each frozen-definition entry
is a FROZEN REQUIREMENT unless it is marked otherwise.

| Entity | Frozen definition | Code at GA | Status | Built in |
|---|---|---|---|---|
| Control | native criterion, `^ISE-[A-Z]+-[0-9]{3}$`, 14 families, JSON data, never executed (D-15, D-111); EXPERIMENTAL lifecycle (D-80, HLD-063) | `scripts/ci/native_controls.json`, read only by CI; `criteria` is empty | IMPLICIT | v0.3 |
| Control version | required `version` field; evaluation records the rules version (SNAP-013) | CI JSON only | MISSING | v0.3 |
| Check specification | `facts_required`, `dimensions`, `evaluation_semantics`, `applicability`, `limitations`, `evidence_pointers` (`NATIVE_CONTROL_CATALOG.md`) | none; `lib/isedraf/shared/compare.py` compares two sources against each other, not against an expected value | MISSING | v0.3 |
| Run | `run_id`, `snapshot_id` (SNAP-019); collect each domain once (D-117) | `lib/isedraf/audit.py` `collect()`; the run status is printed but never stored | PARTIAL | v0.2 |
| Observation classes | `STATE`/`OBSERVATION`/`DERIVED`/`PROVENANCE`, mandatory per field (SCOPE-045, D-102) | per-domain `CLASSIFICATION` tables; the constants are defined four times; enforced in tests only | PARTIAL | v0.2 |
| Evidence | evidence reference object (SNAP-016); D-115 auxiliary binding | `lib/isedraf/shared/result.py` `Evidence`; section digests in `manifest_core`; hash-chained ledger; independent verifier | EXISTS | v0.2 extends |
| Collector method identity | collector, collector version, parser version, source, classification table version (CMP-020) | only `lib/isedraf/identity.py` carries it; the ten audit sections share one schema version | PARTIAL | v0.2 |
| Coverage / evidence limits | Evidence Limits Manifest (bound by D-115 when produced; field schema not frozen) | `lib/isedraf/coverage.py` exists; `isedraf audit` never writes `coverage/evidence_limits.json` | PARTIAL | v0.2 |
| Capability registry | capability-driven, never distro-driven (D-14); collectors declare privilege and mutation (HLD-031) | the hard-coded `audit.COLLECTORS`; no declared capabilities or provided facts | IMPLICIT | v0.2 |
| Evaluation result | three disagreeing lists (see §4) | none | MISSING | v0.3 |
| Finding | only in `evaluations/EVL-*/findings.json`, never in a snapshot (HLD-032, SNAP-011/012); also produced by MANUAL_REVIEW (SCOPE-023) and scope changes (IDENT-041) | none; `lib/isedraf/ids.py` has no `EVL` prefix | MISSING | v0.3 |
| Baseline / delta | fully specified (BASE-001…030, CMP-020…031, DELTA-001…021) | none; `lib/isedraf/stateroot.py` deliberately does not create `baselines/` or `evaluations/` | MISSING | v0.4 |
| Framework mapping | overlay that never changes A (D-112); clean room (D-63); strength and lifecycle enums (HLD-063) | none; `scripts/ci/framework_sources.json` has no sources | MISSING by design | v0.5 |
| Severity | not defined; HLD-020 forbids a compliance percentage | none | NOT DEFINED | owner decision (IQ-041) |

INFERENCE: the foundation is real. Collection, normalization, provenance, digests, the ledger and
verification can carry the model above without a rewrite. What is missing is the assurance layer:
the catalog content, evaluation, findings and history.

## 3. The contract between v0.2 and v0.3

PROPOSAL. v0.2 produces evidence that v0.3 consumes as it is. v0.2 builds no control engine, and
v0.3 adds no second collection path.

```text
v0.2 guarantees, for every section      v0.3 adds, reading only committed evidence
  observation, with field classes          ISE-* criterion (catalog data)
  source and provenance                    applicability
  collection time                          expected state (evaluation_semantics)
  collector identity and version (CMP-020) evaluation -> result
  privilege level and authority class      finding, in evaluations/EVL-*/
  integrity (digest, D-115 binding)
  completeness (collection status,
    evidence limits)
```

Each v0.2 guarantee should extend a structure that already exists, not run beside it:

| Guarantee | Existing structure to extend |
|---|---|
| observation and field classes | the per-domain `CLASSIFICATION` tables; one shared definition of the four constants |
| collector identity | the CMP-020 method identity, carried per section as `identity.py` already does |
| completeness | `lib/isedraf/coverage.py` and the Evidence Limits Manifest (D-115), once its field schema is frozen |
| capability | `audit.COLLECTORS`, extended with declared capabilities, provided facts and version, not replaced |
| integrity | `manifest_core.auxiliary_artifacts` and the D-50 commit boundary, with no second commit mechanism |

**Duplication risks to avoid in v0.2 and v0.3.** These are places where a second model could
appear beside the first one:

1. A runtime control catalog separate from `scripts/ci/native_controls.json`, which `make
   check-native-catalog` would not see.
2. A new result enumeration added before IQ-040 picks one of the three that already exist.
3. A capability registry separate from `audit.COLLECTORS` and `SECTION_NAMES`.
4. A fifth copy of the field-class constants.
5. An evaluator that re-derives completeness instead of reading `coverage.py`.
6. A second report model instead of a new key in `lib/isedraf/report/model.py`.
7. A delta engine built on the `MODIFIED` relationship in `compare.py`, which compares sources, not
   points in time.
8. `docs/reference/CONTROL_EVIDENCE_MAP.md` turning into a hand-maintained control list.

## 4. How the 2026-10 proposal fits the frozen model

The proposal (a canonical control → check specification → observation → evidence → evaluation →
result → finding chain, independently written controls, and framework content as separate mapping
data) matches the frozen model in substance. Where its details differ, the frozen text wins.
Anything that would change it goes to the owner as an amendment.

| Proposal item | Frozen authority | Disposition |
|---|---|---|
| IDs like `ISEDRAF-SSH-001` | D-111: `ISE-SSH-001` | use `ISE-*`; no rename |
| YAML control files | D-15: JSON data; EXEC-016: no stdlib YAML parser | JSON |
| JSON Schema files under `schemas/v1/` | D-103: JSON Schema in CI only, structural check at runtime; OUT-011: 0.x schema versions | CI schemas plus a runtime structural check; version naming to settle in v0.3 |
| results PASS/FAIL/UNKNOWN/NOT_APPLICABLE/ERROR | CMP-001/CMP-002: collection status and evaluation result never merge; `ERROR` and `NOT_TESTED` are collection statuses | keep the two axes apart; choose the result list through IQ-040 |
| "UNKNOWN → assessment limitation" | criterion `limitations`; the report's evidence-limitations boundary (D-112 product HLD) | already covered under the frozen names |
| Result 1:1 Execution, Execution 1:N Evidence | evidence is per snapshot section, collected once and shared (HLD-050, D-117); results are regenerable evaluations of a snapshot (SNAP-012) | snapshot 1:N sections; evaluation (snapshot × rules version) 1:N results; result 0:N findings |
| FAIL is the only source of a finding | SCOPE-023, IDENT-041 | findings also come from MANUAL_REVIEW and scope changes |
| `remediation_hint` on the finding | optional `remediation_guidance` on the criterion; ILLUSTRATIVE, with operational risk (DELTA-020/021, OUT-014); clean room (D-63) | criterion field, frozen name |
| severity critical … info | not defined; HLD-020 | owner decision (IQ-041) |
| licensing classes OPEN / REFERENCE-ONLY / USER-SUPPLIED | D-112 Modes A/B/C; D-63 identifiers plus independent objectives | Mode B ≈ OPEN; D-63 covers REFERENCE-ONLY; USER-SUPPLIED becomes Mode C, which needs a written provider agreement |
| `isedraf framework import` | not in the CLI surface | v0.5 at the earliest, under Mode C |
| `controls list/show`, `check --control/--family` | `explain <id>` already covers controls (HLD-051) | v0.3 CLI design; needs a surface amendment |
| controls running `sshd -T` | EVID-001, SCOPE-020/021; generally needs root | NOT_TESTED until v0.2 provides authority |
| `find /` scans | D-67, SCOPE-031: local filesystems only, no mount crossing, time budget; HLD-011: no whole-filesystem integrity monitoring; SCOPE-060 | bounded scans only, never a canonical `find /` |
| proposed first controls | — | drop "SSH protocol 2" (obsolete); split "password hash strength" into state classification and policy; `/tmp nodev` needs the normalized mount observation (namespace, filesystem type) |
| privileged Rust collectors outside v0.2 | ROADMAP; D-12; EXEC-016 | consistent: the v0.2 worker may be Python with fixed operations; the compiled core is measurement-gated and needs an amendment |

## 5. Version labels in frozen text

The new sequence moves two capabilities away from the version labels that frozen text gives them.
The frozen text is not edited here. IQ-039 asks the owner for an amendment.

- D-65, OD-08 and the "Framework mapping column" in `docs/reference/CONTROL_EVIDENCE_MAP.md` place
  mapping views in v0.2. They are now v0.5.
- SCOPE-050 places baseline approval and delta in the W1 vertical slice. They are now v0.4, behind
  the authority that v0.2 provides.

## 6. Recorded for the owner

| IQ | Type | Question |
|---|---|---|
| IQ-039 | CONFLICT | amend the frozen version labels (D-65, OD-08, SCOPE-050) to the 2026-10-05 sequence |
| IQ-040 | CONFLICT | one evaluation-result vocabulary: the catalog's four states or the seven in D-35/CMP-001; `PARTIAL` currently means one thing as a collection status and another as a result |
| IQ-041 | GAP | whether native criteria carry a severity at all, and if so how it fits HLD-020 |
| IQ-042 | GAP | v0.2 evidence contract: per-section CMP-020 method identity, and the Evidence Limits Manifest that `isedraf audit` does not write |
| IQ-043 | DEFECT | the status registry lists users and groups, sudo, SSH, PAM and mounts as `PLANNED`, although `isedraf audit` collects them |

None of these stops the 0.1.0 release that is already published.
