<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Native Criterion Engineering & Evidence Protocol (v0.3)

Status: PLANNING

Proposed; owner review required.
Implements: D-111, D-121, D-125

The fixed path every native `ISE-*` criterion follows, from selection to owner acceptance, and the
evidence each step leaves behind. It documents existing contracts (`D-111`, `D-121`, `D-125`,
`EVAL-001` … `EVAL-009`). It adds no gate, schema, field, namespace or source of truth. The
authoritative definition of a criterion stays `lib/isedraf/catalog/native_controls.json`; an
acceptance record under `docs/development/criteria/` is an evidence index, never a second definition.

The reference implementation is `ISE-ACCOUNT-001`
(`docs/development/criteria/ISE-ACCOUNT-001_ACCEPTANCE.md`). Copy the process, never its results.

## 1. Objective

Every criterion has one stable identity and one catalog record, uses verified committed evidence
only, never yields an unsupported `PASS` or `FAIL`, evaluates deterministically, is reachable through
`isedraf evaluate`, `isedraf explain`, the report and its generated page, and has identifiable
acceptance evidence and stated limitations. Quality and truthfulness come before rule count.

## 2. Lifecycle

A stage is complete only when its evidence exists. Planned work is never reported as implemented or
validated.

| Stage | Activity | Evidence |
|---|---|---|
| 01 SELECT | choose a candidate whose facts are already committed | justification, and the evidence route of section 4 |
| 02 DEFINE | owner admission under `D-111` | owner-signed catalog record |
| 03 MAP | required facts and their sources | evidence coverage matrix (section 4) |
| 04 SPECIFY | applicability and result semantics | decision table (section 5) |
| 05 IMPLEMENT | pure deterministic evaluator | code and focused tests |
| 06 FALSIFY | challenge every result and refusal boundary | tests and injections, all firing |
| 07 INTEGRATE | EVL, explain, report, generated page | integration tests |
| 08 PACKAGE | installed artifacts | DEB and RPM payload evidence, hashes |
| 09 VALIDATE | one bounded supported-platform acceptance | lab evidence, EVL artifacts retained |
| 10 ACCEPT | owner review and disposition | commit, tree, hashes, decision |

Admission (02 to 04) and implementation (05 to 09) are separate owner-applied kits. One kit may
carry several criteria, but every criterion keeps its own record, tests and injections.

## 3. The criterion record

The catalog fields are the ones `D-111` fixes: `criterion_id`, `version`, `check_type`, `purpose`,
`rationale`, `facts_required`, `dimensions`, `evaluation_semantics`, `applicability`,
`limitations`, `evidence_pointers`, `default_severity`, and optionally `manual_verification` and
`remediation_guidance`. Two things are often asked for and are not fields:

- **A rule name or title.** The schema has none. The name is stated in the first sentence of
  `purpose`. Adding a field is a separate `D-111` amendment.
- **A lifecycle status.** Every prototype control is `EXPERIMENTAL` (`D-80`). The engine states it;
  the record does not carry it.

`evidence_pointers` are executable. The evaluator declares the pointers it reads and refuses to run
unless they equal the record's (`D-125`). A pointer written for a reader rather than for the code
is a defect, and the first slice had one.

## 4. Evidence coverage matrix (stage 03)

Fill this in before any code. The **route** column is mandatory: it says which run produces the fact.

| Required fact | Section and pointer | Route that produces it | Completeness requirement | Missing or incomplete |
|---|---|---|---|---|
| … | `sections/<name>.json` `/evidence/…` | Standard Audit, or Full Audit only | e.g. source `COLLECTED`, no INCLUDE | `NOT_EVALUATED`, reason naming the source and its status |

**Route rule.** A fact that only a Full Audit produces (anything read through a fixed privileged
operation: `/etc/shadow`, `sshd -T`, the sudoers graph) is never in a Standard Audit snapshot.
`isedraf evaluate` evaluates the unprivileged stores only, until system-store evaluation is
admitted (`EVAL-008`). Such a criterion therefore yields `NOT_EVALUATED` on every host it can run on
today. That is a correct result, but it is not evidence that its `PASS` or `FAIL` works on a real
host. The record must say so, and the owner decides whether to admit it before `EVAL-008` is
implemented.

A verified snapshot is necessary, not sufficient: a fact can still be incomplete, out of scope or
unobservable. The evaluator never reads a live file and never starts a collection.

## 5. Decision table (stage 04)

Write only the results the criterion can justify. Never invent conditions to exercise every state.

| Evidence and condition | Result |
|---|---|
| complete evidence, condition holds | `PASS` |
| complete evidence, violation demonstrated | `FAIL` |
| a required source not `COLLECTED`, or the fact's domain not fully observed | `NOT_EVALUATED` |
| facts collected, a human judgement genuinely required | `MANUAL_REVIEW` |
| evidence positively shows the subject is absent | `NOT_APPLICABLE` |
| a value the evidence model does not define, or integrity fails | refused: exit `64`, no EVL |

Malformed is not insufficient. An undefined value is refused; only a defined state of the evidence
model that cannot support a conclusion is `NOT_EVALUATED`. A successful evaluation can record a
`FAIL`; the exit code reports execution, never the security result (`EVAL-007`).

## 6. Determinism and integrity

The same verified snapshot, engine and catalog give byte-identical artifacts. Evaluation never
changes the snapshot or the ledger. Re-evaluation is a no-op, and a different artifact under the
same identity is refused, never overwritten. Results and findings stay separate (`D-121`
section 5). An unverifiable snapshot never yields a result. `report` never evaluates.

## 7. Tests and falsification (stages 05 to 07)

Minimum, per criterion: each justified result; each insufficient-evidence path; malformed and
contradictory evidence refused; integrity refusal; deterministic regeneration; no collection and no
host change; exit codes and the root refusal; `explain` and report consistency with the record; one
falsification injection per evaluator boundary, all firing. Invalid states come from synthetic
fixtures or real fixture audits, never from damaging a lab host. A host reporting `PASS` does not
prove the negative branches; fixtures and injections do.

## 8. Presentation

`isedraf explain`, the evaluation, the report and the generated page render the one record. An
operator can answer: what was evaluated, why it matters, which evidence, what was observed, which
limitations apply, why the result is justified, and what needs a person. There is no hand-written
second description.

## 9. Platform acceptance (stage 09)

Once per batch, after integration, on the five acceptance platforms. Record per platform: platform
and version, package artifact and SHA-256, source commit and tree, criterion ID and version, result
and reason code, run mode, EVL integrity and determinism, CLI, report and explain behaviour,
supported and unsupported routes, platform anomalies.

**Retain the EVL artifacts themselves** in the evidence directory, not only a summary of them. The
first slice's lab run summarised them and they had to be fetched afterwards.

**Install procedure.** A candidate built at an unchanged version has the same package version as the
published build. rpm 4.14 (EL8) refuses `--replacepkgs` when the files differ, so remove the package
first, then install. Removing a package never touches an evidence store.

## 10. Acceptance record

One file per criterion, `docs/development/criteria/<criterion_id>_ACCEPTANCE.md`, with the catalog
ID and version, the coverage matrix and decision table (as references to the record, not copies of
it), fixtures and test names, falsification results, the implementation commit and tree, package
hashes, lab results with the evidence directory and its checksum, limitations, open issues, and the
owner disposition (`PENDING`, `ACCEPTED`, `REJECTED` or `DEFERRED`). Commits are cited by hash;
amendment numbers are cited only in `AMENDMENTS.md` (`D-106`).

## 11. Scope control

This protocol authorizes no new collector, family, numbering change, remediation, policy subsystem,
framework-driven semantics, repeated full-fleet runs, or change to a frozen contract. A demonstrated
missing fact or authority requirement is escalated as an implementation question, not worked
around.
