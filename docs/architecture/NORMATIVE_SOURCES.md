<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Normative Source Registry

Implements: D-105, D-106, GOV-001

**Each normative concept has exactly one authoritative definition.** Other documents reference it by
requirement ID. They SHALL NOT restate formulas, paths, state machines or topology independently.

This registry is the structural fix for the failure that produced repair-induced blockers in three
consecutive review rounds: the ideas were sound, but the same truth was written down in several places and
repairs reached only some of them. One ledger path existed in four documents; one baseline formula in
three; one privilege topology in three, in two incompatible orderings.

| Concept | Normative source | Document |
|---|---|---|
| Execution topology and modes | `PRIV-005` | Evidence and Trust Model |
| Sandbox unit properties | `EXEC-001` | Evidence and Trust Model |
| Capability ceiling | `PRIV-009` | Evidence and Trust Model |
| Canonical serialization | `NORM-035` | Snapshot/Baseline/Delta |
| Hash framing and domains | `NORM-038` | Snapshot/Baseline/Delta |
| Golden vectors | `NORM-039` | Snapshot/Baseline/Delta |
| Baseline revision computation | **W1: `SCOPE-074`** · Freeze Set 2: `BASE-001` | v0.1 Scope / Snapshot |
| Baseline policy object | `BASE-005` | Snapshot/Baseline/Delta |
| Baseline event object | `BASE-006` | Snapshot/Baseline/Delta |
| Baseline storage and verification | `BASE-007` | Snapshot/Baseline/Delta |
| Tracking vs completeness | `BASE-020`…`BASE-025` | Snapshot/Baseline/Delta |
| Storage layout | `STORE-001` | Snapshot/Baseline/Delta |
| Ledger storage and recovery | `STORE-010`, `STORE-016` | Snapshot/Baseline/Delta |
| Collection method identity | `CMP-020` | Snapshot/Baseline/Delta |
| Field classification | `SCOPE-045` | v0.1 Implementation Scope |
| Exit codes | `OUT-001` + `lib/isedraf/exitcodes.json` | HLD (data file is the source) |
| Rendering guards | `OUT-012`…`OUT-016` | HLD |
| Personal-data map | `OUT-020` | HLD |
| Header grammar | `HDR-001` | Header Policy |
| AI attribution | `D-93` | Decisions Register |
| Amendment authority | `D-106` | Decisions Register |

## The rule

**NRM-001 SHALL** A document other than the normative source MAY cite the requirement ID and summarize its
intent in one sentence. It SHALL NOT restate the formula, the path, the enumeration or the state machine.

**NRM-002 SHALL** When a normative source changes, only the source changes. Referencing documents need no
edit, because they carry no competing copy.

**NRM-003 SHALL** A concept that acquires a second normative definition is a defect, whether or not the
two agree — they will diverge at the next repair.
