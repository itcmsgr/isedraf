<!--
SPDX-License-Identifier: MPL-2.0
SPDX-FileCopyrightText: Copyright (c) 2026 Antonios Voulvoulis / ITCMS
-->
# Evidence Limits Manifest — Schema 2

Implements: D-122, D-115, D-121, CMP-001, SCOPE-022

**Frozen by owner decision 2026-10-06 (`D-122`).**

This document freezes the content of `coverage/evidence_limits.json`, the Evidence Limits Manifest.
D-115 already binds that file into a snapshot through `manifest_core.auxiliary_artifacts`, outside
`state_hash`. This schema fixes what the file says. It is frozen by D-122 and changes only by owner
amendment. `scripts/ci/check_evidence_limits_schema.py` holds it to its fixtures and to the code.

**One representation.** The manifest is the output of `lib/isedraf/coverage.py`, which is already
the single authority for acquisition coverage. Schema 2 freezes that structure and adds three things
it lacked: collector identity, per-source acquisition authority, and an explicit record of omitted
scope. It introduces no second vocabulary. Every enumerated value below is the value `coverage.py`
or `lib/isedraf/status.py` already defines, and the gate fails if the two ever differ.

## 1. What the manifest is, and what it never is

**ELIM-001 (D-122) SHALL** The manifest describes the limits of the evidence one run collected: which
sources the run set out to acquire, what happened to each, and what that means for interpreting the
evidence. It is a statement about observation capability, never about host state, and never an
evaluation.

**ELIM-002 (D-122, D-121, CMP-001) SHALL NOT** The manifest carries no evaluation semantics. No field
holds, and no value may be, an evaluation result (`PASS`, `FAIL`, `NOT_APPLICABLE`, `MANUAL_REVIEW`,
`NOT_EVALUATED`), a severity (`critical`, `high`, `medium`, `low`), or any verdict, score or
percentage. `status` is the collection status of CMP-001 and nothing else.

**ELIM-003 (D-122) SHALL NOT** The absence of a record never implies complete or authoritative
coverage:
1. a source that does not appear in the manifest is unknown, not complete;
2. a requested section must appear, either through at least one source entry or in
   `unreported_sections` (ELIM-011);
3. a snapshot without the manifest has coverage NOT ESTABLISHED, and no consumer may treat that as
   complete;
4. completeness is counted only from explicit entries (ELIM-012).

**ELIM-004 (D-122) SHALL NOT** The manifest does not represent the run privilege mode, the
tool-integrity level or any evaluation. Per-source acquisition authority (ELIM-008) is a separate
concept from each of them, and none is derived from another.

## 2. The per-source record

Each entry of `sources` describes one acquisition attempt. The seven frozen concepts map onto fields
as follows.

| Concept | Fields | Meaning |
|---|---|---|
| section / source | `domain`, `source` | `domain` is the snapshot section that requested the source (an audit section name, or `host_identity`); `source` is the source identifier that section uses, a collection-root-relative path or a stable operation name |
| collector identity | `collector` | an object: `collector_id`, `collector_version`, `parser_version` |
| authority | `acquisition_mode`, `operation_id` | how this acquisition was attempted (ELIM-008) |
| collection status | `status`, `access_outcome`, `operation` | what was attempted and what came back |
| omitted scope | `source_universe`, `universe_reasons` | whether the source's own bounded universe was fully observed, and if not, why |
| reason | `reason` | why the status is not `COLLECTED` (ELIM-009) |
| impact on interpretation | `privilege_limited`, `required_access`, `affects_completeness`, `absence_claim_allowed` | derived consequences (ELIM-010) |

`note` is optional informational text. No consumer may interpret it.

**ELIM-005 (D-122) SHALL** A source entry has exactly these keys, and no others:

```text
domain                 string, non-empty
source                 string, non-empty
collector              object {collector_id, collector_version, parser_version}, each a non-empty string
acquisition_mode       enumerated (vocabulary "acquisition_mode")
operation_id           null in schema 2 (reserved, ELIM-008)
operation              enumerated ("operation")
status                 enumerated ("status")
access_outcome         enumerated ("access_outcome")
reason                 null, or a string in the ELIM-009 grammar
source_universe        enumerated ("source_universe")
universe_reasons       sorted list of unique tokens [A-Z][A-Z0-9_]*
note                   null, or a string
privilege_limited      boolean, derived
required_access        enumerated ("required_access"), derived
affects_completeness   boolean, derived
absence_claim_allowed  boolean, derived
```

**ELIM-006 (D-122, CMP-020) SHALL** `collector` is structured method identity. It identifies the
code that produced the observation, so that a collector or parser change is never read as a host
change. It is part of the record but not of the coverage digest (ELIM-014): a new collector version
is a method change, which CMP-020 tracks, and not by itself a change in what the run could observe.

**ELIM-007 (D-122) SHALL** `source_universe` and `universe_reasons` agree. `COMPLETE` and
`NOT_APPLICABLE` carry an empty `universe_reasons`. `INCOMPLETE` carries at least one token, so
incompleteness is never silent. The tokens are the requesting section's own vocabulary, for example
`CANDIDATE_NOT_OBSERVED`.

**ELIM-008 (D-122) SHALL** `acquisition_mode` records the authority under which this one source was
acquired. Schema 2 admits exactly the values in the "acquisition_mode" vocabulary below, which today
is `CURRENT_IDENTITY`: the engine attempted the acquisition as the identity it was already running
as, and elevated nothing. `operation_id` is reserved for the identifier of a fixed privileged
operation, and is `null` for every schema 2 entry. The Full Audit amendment adds the supervisor
value and defines `operation_id`. That extension changes no existing manifest, and a verifier that
predates it rejects an unknown value rather than trusting it.

**ELIM-009 (D-122, SCOPE-022) SHALL** `reason` is `null` exactly when `status` is `COLLECTED`.
Otherwise it is a string of the form `CODE: text`, where `CODE` matches `[A-Z][A-Z0-9_]*`. The
code is the machine-readable part; the text is for people.

**ELIM-010 (D-122) SHALL** The four impact fields are derived and are never authored by a domain.
Their values equal the functions in `lib/isedraf/coverage.py` applied to the entry's facts:

```text
privilege_limited      = access_outcome == PERMISSION_DENIED
required_access        = ACCESS_NONE unless access_outcome == PERMISSION_DENIED;
                         otherwise the class for the operation, or
                         ACCESS_ADDITIONAL_AUTHORITY_UNSPECIFIED
affects_completeness   = status != COLLECTED or source_universe == INCOMPLETE
absence_claim_allowed  = source_universe in (COMPLETE, NOT_APPLICABLE)
```

A verifier recomputes them and rejects any disagreement.

## 3. The manifest

**ELIM-011 (D-122) SHALL** The manifest object has exactly these keys:

```text
schema_version              2
requested_sections          sorted list of unique section names the run requested
unreported_sections         sorted list of {section, reason}: requested sections with no source entry
acquisition_modes           sorted set of the entries' acquisition_mode values, derived
requested_sources           count of source entries, derived
complete_sources            entries with affects_completeness false, derived
partial_sources             entries with status PARTIAL, derived
privilege_limited_sources   entries with privilege_limited true, derived
other_unavailable_sources   entries affecting completeness that are neither privilege-limited
                            nor PARTIAL, derived
required_access             sorted set of the entries' required_access other than ACCESS_NONE, derived
sources                     the source entries, sorted by (domain, source), each pair unique
limitations                 the entries with affects_completeness true, in the same order, derived
coverage_digest             ELIM-014
```

Every name in `requested_sections` appears either as the `domain` of at least one entry or as the
`section` of exactly one `unreported_sections` item, and never as both. Every entry's `domain` is in
`requested_sections`. An `unreported_sections` item records a section that produced no coverage, for
example because its collector failed. Its `reason` follows ELIM-009 and is never null.

**ELIM-012 (D-122) SHALL** Counts are over the explicit requested universe: the source entries.
There is no percentage and no field that could express "complete because of how the run was
executed". Root is not completeness.

**ELIM-013 (D-122) SHALL** The file is the canonical serialization of the manifest
(`lib/isedraf/canonical.py`, NORM rules): object keys sorted, no insignificant whitespace, one
trailing newline. Every list whose order is not defined above is sorted. Two runs that observe the
same coverage produce byte-identical manifests, apart from the fields that legitimately differ.

**ELIM-014 (D-122) SHALL** `coverage_digest` identifies what the run could observe, not what it
found. It is `canonical.hash_frame` under the domain `ISEDRAF:EVIDENCE-COVERAGE:V2` over the
canonical bytes of:

```text
{schema_version, requested_sections, unreported_sections,
 sources: [{domain, source, operation, acquisition_mode, status, access_outcome,
            source_universe, universe_reasons}, ...]}
```

The entries are taken in manifest order, and the digest is rendered with `canonical.rendered`.
Collector identity, the reason text, notes and the derived fields are excluded. Two runs of an
unchanged host that differ only in what the collector could read produce different coverage digests
and identical host state.

## 4. Vocabularies

The gate requires this block to equal the code: `operation`, `access_outcome`, `required_access`,
`acquisition_mode` and `source_universe` must equal `lib/isedraf/coverage.py`, and `status` must
equal `lib/isedraf/status.py`.

```json evidence-limits-vocabulary
{
  "schema_version": 2,
  "digest_domain": "ISEDRAF:EVIDENCE-COVERAGE:V2",
  "status": ["COLLECTED", "PARTIAL", "NOT_TESTED", "ERROR"],
  "operation": ["FILE_READ", "FILE_METADATA", "DIRECTORY_LIST", "COMMAND", "KERNEL_INTERFACE",
                "SERVICE_QUERY"],
  "access_outcome": ["READ_OK", "NOT_FOUND", "PERMISSION_DENIED", "IO_ERROR", "NOT_SUPPORTED",
                     "TRUNCATED"],
  "required_access": ["ACCESS_NONE", "ACCESS_FILE_READ", "ACCESS_DIRECTORY_TRAVERSE",
                      "ACCESS_COMMAND_QUERY", "ACCESS_KERNEL_INTERFACE", "ACCESS_SERVICE_QUERY",
                      "ACCESS_ADDITIONAL_AUTHORITY_UNSPECIFIED"],
  "acquisition_mode": ["CURRENT_IDENTITY"],
  "source_universe": ["COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"],
  "forbidden_values": ["PASS", "FAIL", "NOT_APPLICABLE", "MANUAL_REVIEW", "NOT_EVALUATED",
                       "critical", "high", "medium", "low"]
}
```

`NOT_APPLICABLE` appears in `source_universe` (a source whose universe question does not arise)
and in `forbidden_values` (the evaluation result). ELIM-002 forbids the evaluation result in every
field except `source_universe`, where the token has its own frozen meaning.

## 5. Schema 1 and what changes

`coverage.py` emits schema 1 today, and no production run writes the file yet (IQ-042). Schema 2 is
what the first production writer emits. The differences:

| Schema 1 | Schema 2 |
|---|---|
| one `acquisition_mode` for the whole manifest | `acquisition_mode` per source; the manifest keeps the derived set `acquisition_modes` |
| no collector identity | `collector` per source (ELIM-006) |
| `source_universe` alone | `source_universe` plus `universe_reasons` (ELIM-007) |
| no section accounting | `requested_sections` and `unreported_sections` (ELIM-011) |
| `reason` free text, optional | ELIM-009 grammar, required when not `COLLECTED` |
| digest domain `…:V1` | `ISEDRAF:EVIDENCE-COVERAGE:V2` over the ELIM-014 frame |

Every other field keeps its schema 1 name and meaning. `docs/development/R15P_PRIVILEGE_AND_EVIDENCE_CONTRACT.md`
§5 sketched an indicative shape before `coverage.py` existed. This schema supersedes that sketch.

## 6. Fixtures

`tests/fixtures/evidence_limits/v2/valid/` holds manifests that must pass the gate.
`tests/fixtures/evidence_limits/v2/invalid/` holds manifests that must fail it, each named after the
requirement it violates.
