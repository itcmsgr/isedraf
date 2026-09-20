<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Glossary

Status: IMPLEMENTED
Implements: D-89, §20

Canonical meanings. No other document may redefine a term listed here. Gate C-03 rejects unknown status
values in documentation.

## Core model

**Snapshot** — an immutable record of normalized host state at one point in time. Contains state and
evidence references. Never contains changes or findings. Directory `snapshots/SDS-*`.

**Baseline** — an approved snapshot plus an ordered list of acceptances. *Accepted, not secure.*

**Baseline revision** — `BL-n`, derived from the approved snapshot hash plus the acceptance records. A new
acceptance produces a new revision.

**Acceptance** — an explicit record that a specific change is approved. Binds the exact accepted normalized
state hash, so any later change to that entity is a new change.

**Evaluation** — derived and regenerable output keyed by snapshot, baseline revision, engine version and
rules version. Directory `evaluations/EVL-*`.

**Delta** — the classified difference between a snapshot and the effective baseline.

**Finding** — an evaluated result about a control or entity, living in an evaluation, never in a snapshot.

**Ledger** — `ledger/segment-NNNNNN.jsonl`, append-only **within a segment** and hash-chained. IDs and
hashes only. Authoritative for which snapshots exist. Normative definition: `STORE-010`.

## Evidence

**Evidence** — the collected material a statement rests on, with its source recorded.

**State** — canonicalized, hashed and diffed. Drives change detection.

**Observation** — displayed but never hashed or diffed. Last login, PID, uptime, journal size,
"days remaining". **Never causes `CHANGED`.**

**Declared** — configured in a source file.
**Resolved** — computed by the subsystem itself (for example `sshd -T`).
**Active** — currently loaded in the kernel or process.
`MISMATCH` means resolved ≠ active.

**Host evidence boundary** — the limit of what ISEDRAF assesses: state directly observable on the local
operating system. Outside it, ISEDRAF reports nothing rather than guessing.

**Provenance** — where a fact came from and how it was obtained.

## Collection status

Separate from evaluation result, with separate counters.

`COLLECTED` · `PARTIAL` · `NOT_TESTED` (not attempted or not possible, with a reason) · `ERROR`.

## Evaluation result

`PASS` · `FAIL` · `PARTIAL` · `MISMATCH` · `NOT_APPLICABLE` · `MANUAL_REVIEW` · `NOT_EVALUATED`.

**`NOT_TESTED` is never `PASS`.** It never becomes `REMOVED` and never becomes an improvement.

## Comparability

**`NOT_COMPARABLE`** — the two sides cannot be meaningfully compared; always carries a reason. Produced
when either side was not `COLLECTED`, or when the collection method changed incompatibly.

**`COLLECTION_METHOD_CHANGED`** — collector or parser version differs. Identical normalized values are
silent; differences are `REVIEW_REQUIRED`.

**`baseline rebind`** — re-anchor a baseline to a new collection method. Equivalent state → `SAFE_REBIND`;
different → `REVIEW_REQUIRED`. **Never auto-accepts new state.**

**`BASELINE_NOT_APPLICABLE`** — host identity does not match the baseline's host. No diff is produced.

**`ORPHANED`** — a snapshot directory with no ledger entry.

## Change primitives and interpretation

Primitives: `ADDED` · `REMOVED` · `MODIFIED` · `ENABLED` · `DISABLED` · `MISMATCH`.

Interpretations: `SECURITY_REGRESSION` · `SECURITY_IMPROVEMENT` · `EXPECTED_CHANGE` (only with correlating
evidence) · `REVIEW_REQUIRED` · `INFORMATIONAL`.

**Security regression** — an observed change that reduces the host's security posture as defined by the
interpretation rules. It is a classification of observed state, not a claim about exploitability.

## Account creation provenance

`EVENT_RECORDED` — supported by trusted evidence: an auditd `ADD_USER` record, or a journal entry whose
trusted fields show `_UID=0` and the real account-management binary. Message text alone is never trusted.
ISEDRAF does not claim the record cannot be altered: root can rewrite local logs.
`ESTIMATED` — an estimate such as home-directory birth time, carrying source, confidence `LOW` and an
explanation.
`UNKNOWN` — no adequate evidence. Rotated evidence yields `UNKNOWN`, never a guess.

Password last-change time is never account creation time. The word *verified* is not used for this.

## Integrity

**Tool integrity** — whether ISEDRAF itself is unmodified. Trust levels `LOCAL_CONSISTENT` ·
`PACKAGE_CONSISTENT` · `EXTERNAL_VERIFIED`.

**Host baseline consistency** — whether the host matches its approved baseline.

These are **separate concepts and separate report lines**, always. Local verification detects drift; it
does not defeat a root-level adversary on the same host.

## Lifecycle

Controls: `DRAFT` · `EXPERIMENTAL` · `STABLE` · `DEPRECATED` · `RETIRED`. Prototype controls are
`EXPERIMENTAL`. Retired IDs are never reused.

Mappings: `PROPOSED` · `VERIFIED` · `DISPUTED` · `SUPERSEDED` · `RETIRED`. A mapping is not `VERIFIED`
merely because the control looks related.

## Facts, criteria, scope

**Fact** — canonical evidence: what was observed.
**Criterion** — an independent evaluation applied to that evidence.
**Report** — fact + criterion + result + explanation.

One observed state may legitimately evaluate differently under different criteria.

Scope classes: `HOST_TECHNICAL` · `HOST_SUPPORTING_EVIDENCE` · `MANUAL_ORGANIZATIONAL` ·
`NOT_HOST_ASSESSABLE`.

## Documentation status labels

`IMPLEMENTED` · `EXPERIMENTAL` · `PLANNED` · `FUTURE` · `OUT_OF_SCOPE` · `STUB`.
